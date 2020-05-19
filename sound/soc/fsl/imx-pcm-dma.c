// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * imx-pcm-dma-mx2.c  --  ALSA Soc Audio Layer
 *
 * Copyright 2009 Sascha Hauer <s.hauer@pengutronix.de>
 *
 * This code is based on code copyrighted by Freescale,
 * Liam Girdwood, Javier Martin and probably others.
 */
#include <linux/platform_device.h>
#include <linux/dmaengine.h>
#include <linux/types.h>
#include <linux/module.h>
#include <linux/dma-mapping.h>

#include <sound/core.h>
#include <sound/pcm.h>
#include <sound/soc.h>
#include <sound/dmaengine_pcm.h>

#include "imx-pcm.h"

static bool filter(struct dma_chan *chan, void *param)
{
	if (!imx_dma_is_general_purpose(chan))
		return false;

	chan->private = param;

	return true;
}

static int imx_pcm_hw_params(struct snd_soc_component *component,
			     struct snd_pcm_substream *substream,
			     struct snd_pcm_hw_params *params)
{
	struct snd_pcm_runtime *runtime = substream->runtime;
	struct snd_soc_pcm_runtime *rtd = substream->private_data;
	struct snd_soc_dai *cpu_dai = asoc_rtd_to_cpu(rtd, 0);
	struct snd_dmaengine_dai_dma_data *dma_data;
	struct dma_slave_config config;
	struct dma_chan *chan;
	int ret = 0;

	snd_pcm_set_runtime_buffer(substream, &substream->dma_buffer);
	runtime->dma_bytes = params_buffer_bytes(params);

	chan = snd_dmaengine_pcm_get_chan(substream);
	if (!chan)
		return -EINVAL;

	ret = snd_hwparams_to_dma_slave_config(substream, params, &config);
	if (ret)
		return ret;

	dma_data = snd_soc_dai_get_dma_data(cpu_dai, substream);
	if (!dma_data)
		return -EINVAL;

	snd_dmaengine_pcm_set_config_from_dai_data(substream,
						   dma_data,
						   &config);
	return dmaengine_slave_config(chan, &config);
}

static int imx_pcm_hw_free(struct snd_soc_component *component,
			   struct snd_pcm_substream *substream)
{
	snd_pcm_set_runtime_buffer(substream, NULL);
	return 0;
}

static snd_pcm_uframes_t imx_pcm_pointer(struct snd_soc_component *component,
					 struct snd_pcm_substream *substream)
{
	return snd_dmaengine_pcm_pointer(substream);
}

static int imx_pcm_trigger(struct snd_soc_component *component,
			   struct snd_pcm_substream *substream, int cmd)
{
	return snd_dmaengine_pcm_trigger(substream, cmd);
}

static int imx_pcm_open(struct snd_soc_component *component,
			struct snd_pcm_substream *substream)
{
	struct snd_soc_pcm_runtime *rtd = substream->private_data;
	bool tx = substream->stream == SNDRV_PCM_STREAM_PLAYBACK;
	struct snd_soc_dai *cpu_dai = asoc_rtd_to_cpu(rtd, 0);
	struct snd_dmaengine_dai_dma_data *dma_data;
	struct device *dev = component->dev;
	struct snd_pcm_hardware hw;
	struct dma_chan *chan;
	int ret;

	ret = snd_pcm_hw_constraint_integer(substream->runtime,
					    SNDRV_PCM_HW_PARAM_PERIODS);
	if (ret < 0) {
		dev_err(dev, "failed to set pcm hw params periods\n");
		return ret;
	}

	dma_data = snd_soc_dai_get_dma_data(cpu_dai, substream);
	if (!dma_data)
		return -EINVAL;

	chan = dma_request_slave_channel(cpu_dai->dev, tx ? "tx" : "rx");
	if (!chan) {
		/* Try to request channel using compat_filter_fn */
		chan = snd_dmaengine_pcm_request_channel(filter,
							 dma_data->filter_data);
		if (!chan)
			return -ENXIO;
	}

	ret = snd_dmaengine_pcm_open(substream, chan);
	if (ret)
		goto pcm_open_fail;

	memset(&hw, 0, sizeof(hw));
	hw.info = SNDRV_PCM_INFO_MMAP | SNDRV_PCM_INFO_MMAP_VALID |
			SNDRV_PCM_INFO_INTERLEAVED;
	hw.periods_min = 2;
	hw.periods_max = UINT_MAX;
	hw.period_bytes_min = 256;
	hw.period_bytes_max = dma_get_max_seg_size(chan->device->dev);
	hw.buffer_bytes_max = IMX_DEFAULT_DMABUF_SIZE;
	hw.fifo_size = dma_data->fifo_size;

	/* Refine the hw according to caps of DMA. */
	ret = snd_dmaengine_pcm_refine_runtime_hwparams(substream,
							dma_data,
							&hw,
							chan);
	if (ret < 0)
		goto refine_runtime_hwparams_fail;

	snd_soc_set_runtime_hwparams(substream, &hw);

	/* Support allocate memory from IRAM */
	ret = snd_dma_alloc_pages(SNDRV_DMA_TYPE_DEV_IRAM,
				  chan->device->dev,
				  hw.buffer_bytes_max,
				  &substream->dma_buffer);
	if (ret < 0)
		goto alloc_pagas_fail;

	return 0;

alloc_pagas_fail:
refine_runtime_hwparams_fail:
	snd_dmaengine_pcm_close(substream);
pcm_open_fail:
	dma_release_channel(chan);

	return ret;
}

static int imx_pcm_close(struct snd_soc_component *component,
			 struct snd_pcm_substream *substream)
{
	if (substream) {
		snd_dma_free_pages(&substream->dma_buffer);
		substream->dma_buffer.area = NULL;
		substream->dma_buffer.addr = 0;
	}

	return snd_dmaengine_pcm_close_release_chan(substream);
}

static int imx_pcm_new(struct snd_soc_component *component,
		       struct snd_soc_pcm_runtime *rtd)
{
	struct snd_card *card = rtd->card->snd_card;

	return dma_coerce_mask_and_coherent(card->dev, DMA_BIT_MASK(32));
}

static const struct snd_soc_component_driver imx_pcm_component = {
	.name           = "imx-pcm-dma",
	.pcm_construct	= imx_pcm_new,
	.open		= imx_pcm_open,
	.close		= imx_pcm_close,
	.hw_params	= imx_pcm_hw_params,
	.hw_free	= imx_pcm_hw_free,
	.trigger	= imx_pcm_trigger,
	.pointer	= imx_pcm_pointer,
};

int imx_pcm_dma_init(struct platform_device *pdev, size_t size)
{
	return devm_snd_soc_register_component(&pdev->dev,
					       &imx_pcm_component, NULL, 0);
}
EXPORT_SYMBOL_GPL(imx_pcm_dma_init);

MODULE_LICENSE("GPL");

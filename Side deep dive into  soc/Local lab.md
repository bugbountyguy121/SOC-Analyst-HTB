For your 2015 MacBook Pro with 16 GB RAM, I'd choose a small local Elastic lab with real Windows attack-log samples. That gives you a place to practise KQL repeatedly, investigate different attacks, and learn without depending on your current challenge platform.

## My recommended setup

![Explore Security data in Discover | Elastic Docs](https://images.openai.com/static-rsc-4/VMk2kcasZ7PHk7ESBOjKNroKcOJ_-6a4WlXDkovKCa26fJXe2GBxyEfIrt2oJzD4ejnngLBVd7Se17MfUJ3O1_V8fohI8bl_CI2k_rnsjWDXtSPHORlnky3mxz3b8JhYxwod7CJ_kDg9BDlSIHBrULRaWN3z7lwNmqJ2sCse2-4?purpose=inline)

1. Elastic + Kibana locally

Your query playground

Run Elasticsearch and Kibana on your Linux machine. Discover lets you search individual events and inspect the evidence.

[Official local installation guide](https://www.elastic.co/docs/deploy-manage/deploy/self-managed/local-development-installation-quickstart?utm_source=chatgpt.com)

![GitHub - sbousseaden/EVTX-ATTACK-SAMPLES: Windows Events Attack Samples · GitHub](https://images.openai.com/static-rsc-4/IxLaG6fA4M0ywes8UlIY4LXYy0JU1GgbLgmnipYKz90uHIe7LrBRANvL725T9Q9xHTLNQKv1ySW0PrA1FfS-Epzvn3uN-tHvBsQIl2P5MItVkn97VDIwhc44blR7T1C_ySzlFH1h57wutOsX4Pns4qy4c19p_YqlFA55UM3YKeg?purpose=inline)

2. Windows attack-log dataset

Hundreds of samples

Use [EVTX-ATTACK-SAMPLES on GitHub](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES?utm_source=chatgpt.com). It contains Windows event logs associated with attack techniques, useful for threat hunting, detection development, and DFIR practice.

![](https://www.google.com/s2/favicons?domain=https://github.com&sz=32)

GitHub

+1

Why this combination? The logs give you things to investigate; Elastic gives you a realistic place to practise the queries. The sample dataset is not itself a ready-made Elastic lab, so you'll need to ingest the logs before you can query them.

## Can you install it locally?

Yes. Elastic's official quick-start uses Docker to launch a local Elasticsearch and Kibana environment. The documented setup runs at `localhost:9200` and `localhost:5601`.

![](https://www.google.com/s2/favicons?domain=https://www.elastic.co&sz=32)

Elastic Docs

On Debian, first check whether Docker is installed:

```
docker --version
docker compose version
```

If both commands work, the official setup command is:

```
curl -fsSL https://elastic.co/start-local | sh
```

Review the [official instructions](https://www.elastic.co/docs/deploy-manage/deploy/self-managed/local-development-installation-quickstart?utm_source=chatgpt.com) before running it. This setup is intended for local development, not production.

With your 16 GB RAM, start with just Elasticsearch and Kibana; avoid running several heavy VMs alongside them. It should be a reasonable starting point, although performance depends on available memory, disk space, and the dataset size.

Your learning path: get Elastic running, learn KQL using sample events, then ingest the Windows attack logs and investigate PowerShell, process creation, authentication, and lateral movement.

That gives you one local environment you can keep using, instead of jumping between a dozen resources.
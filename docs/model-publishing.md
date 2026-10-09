# Model library

Yougori stores model uploads and serves downloads. A model publisher does not need a running container or public link to distribute files.

The library accepts LLMs trained or fine-tuned in EU member states and Horizon Europe-associated countries. Publication metadata includes the creator, country, creation method, a rights declaration and optional project evidence. Origin is publisher-declared; Yougori is independent of Horizon Europe. Merely hosting or copying an existing model does not establish its origin.

Upload a model folder at https://yougori.com/publish. Include Safetensors or GGUF weights, configuration, tokenizer, README, license and model code as needed. Uploads are resumable in 8 MiB parts. Parts are SHA-256 verified and stored with adaptive lossless gzip compression and authenticated encryption. Original weights are preserved; storage compression does not quantize a model. Interrupted uploads expire and archived uploads are reclaimed after outstanding operations have drained.

Browse https://yougori.com/modellibrary. Public model downloads do not require sign-in. Private and API-only repositories retain their access controls. Browser downloads include a compressed tar archive and individual original files with HTTP byte-range support. Uploaded code is stored as an artifact and is never executed by the website.

## CLI

Create publication metadata in a JSON file with namespace, slug, name, description, license, visibility, rightsConfirmed, and origin: {country: "FR", creator: "Example research team", creation: "trained", confirmed: true}.

```text
yougori model publish --file metadata.json
yougori model upload yg/PUBLISHER/MODEL --folder ./my-model --version v1
yougori model library
yougori model download yg/PUBLISHER/MODEL --output ./downloaded-model
```

Add --quant Q4_K_M for a GGUF version, or the appropriate stored quantization label for prequantized weights. Retry an upload with the same folder and version to resume. Add --resume UPLOAD_ID to select an existing upload explicitly.

## Inference

Neo Grid inference is separate from file storage. Running an inference provider still requires compute; storing a library model does not create a GPU provider automatically. The library's geographic publication policy does not restrict the separate inference network.

Local/Hugging Face inference commands and --closed-weights (legacy --publish alias) remain available for provider access settings. They do not upload model weights or add a model to the public library. Use the upload flow for library publication. Closed-weight inference is not a claim of hardware-attested confidentiality.

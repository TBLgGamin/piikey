# Third-party notices

piikey is licensed under the MIT License (see [LICENSE](LICENSE)). It uses the
following components that are not Rust crates.

## Detection model

[`bardsai/eu-pii-anonimization-multilang-v2`](https://huggingface.co/bardsai/eu-pii-anonimization-multilang-v2),
Apache-2.0 ([license text](https://www.apache.org/licenses/LICENSE-2.0.txt)).
piikey does not ship it. `piikey.exe` downloads an INT8 ONNX build of it at
first start, from a pinned revision, and checks its SHA-256.

## ONNX Runtime

[ONNX Runtime](https://github.com/microsoft/onnxruntime), Copyright (c)
Microsoft Corporation, MIT License
([license text](https://github.com/microsoft/onnxruntime/blob/main/LICENSE)).
It is linked statically into both executables through the
[`ort`](https://github.com/pykeio/ort) crate.

## DirectML

`DirectML.dll`, the Microsoft DirectML redistributable, is shipped next to the
executables for GPU inference. Microsoft owns it and licenses it under the
terms published with the
[Microsoft.AI.DirectML](https://www.nuget.org/packages/Microsoft.AI.DirectML)
package ([license](https://github.com/microsoft/DirectML/blob/master/LICENSE)).

## Windows App SDK runtime

The Windows App SDK runtime files (`Microsoft.*.dll`, `*.pri`, the
`Microsoft.UI.Xaml` assets and the locale folders) are shipped next to
`piikey.exe` so the app runs without a system-wide install. They come from the
[Microsoft.WindowsAppSDK.Runtime](https://www.nuget.org/packages/Microsoft.WindowsAppSDK.Runtime)
and [Microsoft.Web.WebView2](https://www.nuget.org/packages/Microsoft.Web.WebView2)
NuGet packages and are Microsoft's, under the license terms published with
those packages ([Windows App SDK license](https://github.com/microsoft/WindowsAppSDK/blob/main/LICENSE)).

## Rust crates

The licenses of all Rust crates piikey is built from are in
`THIRD_PARTY_LICENSES.html`, which comes with every release.

## License files

The ONNX Runtime download in the `ort` cache and the NuGet packages as
extracted by `windows-reactor-setup` contain no license text files, so none are
bundled in the release folder. The links above point to the official texts.

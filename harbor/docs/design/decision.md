# Desktop design

Harbor uses a pale gray-green workspace, quiet borders, and a darker green primary action. The main button's white text has approximately 6.16:1 contrast against its background.

The home page holds import, proxy selection, connection mode, and HTTPS verification. First-use guidance collapses while connected so the traffic chart fits in a 980 × 700 window.

The logo forms an H from two piers and a wave. Its SVG is in `desktop/Assets/harbor.svg`. `scripts/build-icons.ps1` generates 16–256 px Windows icons, including connected and stopped tray variants.

The interface uses native WPF controls, custom window chrome, and Microsoft YaHei UI. Scrollbars have a 6 px visible thumb inside a 12 px target. Wheel animation respects the Windows animation preference.

The visual check renders Harbor's own control tree at two window widths. Traffic fixtures use real loopback connections and are labeled as local checks.

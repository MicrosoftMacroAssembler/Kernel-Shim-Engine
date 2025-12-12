# Windows Kernel Shim Engine (KSE)

The Kernel Shim Engine (KSE) is a Windows kernel subsystem that has existed since Windows XP. <br />
It enables patching of driver Import Address Tables (IAT), driver callbacks, and IRP I/O packets. <br />
My documentation provides implementation based on reverse engineering, because the documentation is near to none. <br />

# What Are KSE Shims?
KSE Shims can be applied to:
- Drivers - Patch import tables and callbacks
- Devices - Intercept IRP I/O packets
- Import Address Tables (IAT) - Hook imported functions
- Driver Callbacks - Intercept driver-registered callbacks

# Differences from Traditional IAT Hooking
| Feature | Kse Shim | IAT Hook |
| :---         |     :---:      |          ---: |
| Timing   | Applied before image loads **(before page protection)**     | Applied after page protection    |
| Detection     | Impossible to detect       | Most not all Anti-Cheats detect      |
| Legitimacy     | Used by Windows for compatibility       | Used by malicous software      |
| Performance     | During image load       | Runtime, needs protection bypass      |

# KSE Shim Internals
**The fundamental problem**: Legitimate Shims are applied by `KseDriverLoadImage` **before** `MiApplyImportOptimizationToRuntimeDriver` protects the IAT.  <br />
Our Shims attempt to patch **after** protection is enabled, causing silent failures.  <br />
I go more in-depth about the fundamental problems of our Shims conflict with the legitimate internal KSE flow in the **source codes documentation**.  <br /><br />

<img width="555" height="1509" alt="kse flow" src="https://github.com/user-attachments/assets/a1f3ad6b-0966-4801-b6d5-ae4f95b3e4d8" />
<img width="913" height="968" alt="image" src="https://github.com/user-attachments/assets/67655583-bd48-4037-ab9c-40f95ab6a13c" />
<img width="901" height="933" alt="image" src="https://github.com/user-attachments/assets/9c4ab669-0cc4-455b-a4f4-eac5cf96ab41" />

# Conclusion
KSE provides a **powerful** mechanism for driver shimming, but applying shims at runtime (after page protection) is broken due to **MmReplaceImportEntry failures**.  <br />
Please check out the **source code files** for the **full documentation of the problems and possible solutions** for this concept. <br />
If you find **errors** or have **improvements**, create a issue or contact me on Discord (see profile).  <br />

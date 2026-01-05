# Foobar2000 lyrics components for Mac
<img width="1680" height="1050" alt="image" src="https://github.com/user-attachments/assets/8318ca26-5c41-4a07-81dd-9b3e7b720606" />



Most of the important code related to lyrics APIs are from https://github.com/jacquesh/foo_openlyrics

_There is a lot unecessary files belong to foo_sample which is example component project for foobar_

## Prerequisites

- **Xcode** (with command line tools)
- **Foobar SDK**

## Project Structure

```
foobarSDK/
├── foobar2000/
│   ├── foo_sample/                    # This sample component
│   │   ├── foo_sample.xcworkspace     # Open this in Xcode
│   │   ├── foo_sample.xcodeproj
│   │   └── Mac/                       # macOS-specific source files
│   ├── SDK/                           # foobar2000 SDK
│   ├── helpers/                       # SDK helper library
│   ├── foobar2000_component_client/
│   └── shared/
└── pfc/                               # PFC (Portable Foundation Classes)
```

## Building

### Using Xcode IDE

1. Open `foo_sample.xcworkspace` in Xcode
2. Select the `foo_sample` scheme
3. Choose your destination (e.g., "My Mac")
4. Build using **Cmd+B** or **Product → Build**

### Using Command Line (xcodebuild)

```bash
cd foobar2000/foo_sample

# Build Debug
xcodebuild -workspace foo_sample.xcworkspace -scheme foo_sample -configuration Debug build

# Build Release
xcodebuild -workspace foo_sample.xcworkspace -scheme foo_sample -configuration Release build
```

## Output

After a successful build, the component bundle will be located in Xcode's derived data folder:
```
~/Library/Developer/Xcode/DerivedData/foo_sample-*/Build/Products/<Configuration>/
```

## Installation

1. Copy the compiled `.component` bundle to foobar2000's components directory:
   ```
   ~/Library/Application Support/foobar2000/user-components/
   ```
2. Restart foobar2000

## Dependencies

The workspace includes all required dependencies:

| Project | Description |
|---------|-------------|
| `foobar2000_SDK` | Core SDK interfaces |
| `foobar2000_SDK_helpers` | SDK helper classes |
| `foobar2000_component_client` | Component entry point |
| `pfc` | Portable Foundation Classes |
| `shared` | Shared utilities |

## macOS-Specific Source Files

The `Mac/` folder contains macOS-specific implementations:

- `fooSampleDSPView.h` / `fooSampleDSPView.mm` - DSP UI view
- `fooSampleDSPView.xib` - DSP view interface
- `fooSampleMacPreferences.h` / `fooSampleMacPreferences.mm` - Preferences panel
- `fooSampleMacPreferences.xib` - Preferences interface

## Troubleshooting

### Build Errors
- Ensure all Xcode projects in the workspace are properly referenced
- Clean build folder (**Cmd+Shift+K**) and rebuild

### Missing Dependencies
Make sure you have the complete SDK structure with `pfc`, `SDK`, `helpers`, and `shared` directories.

## Resources

- [foobar2000 SDK Documentation](https://wiki.hydrogenaud.io/index.php?title=Foobar2000:Development:Overview)


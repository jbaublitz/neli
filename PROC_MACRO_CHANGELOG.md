# Changelog

## 0.2.0
### Breaking changes
* Adapt to trait breaking changes introduced in neli v0.7.0. See info in
[CHANGELOG.md][CHANGELOG.md] on `FromBytes` and `FromBytesWithInput` for more
information.

## 0.1.3
### Documentation
* Clean up documentation issues.

## 0.1.2
### Bug fixes
* Fixed bug where the procedural macros did not properly handle empty struct types
resulting in a compilation error
* Fixed bug where attributes were not being appropriately passed to match arms.

## 0.1.1
### Improvements
* Improved debugging that shows only the part of the buffer in question when debugging
an error

### Additions
* Added a `size` attribute for `FromBytes` and `FromBytesWithInput` derive macros

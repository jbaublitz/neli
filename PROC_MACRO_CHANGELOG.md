# Changelog

## 0.1.4
### License
* Add license file to neli-proc-macros

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

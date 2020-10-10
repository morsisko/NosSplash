# NosSplash
Simple script utility that allows you to extract and set custom splash inside EWSF.EWS

# Features
- Easy to install and use
- Support multiple image inputs (auto conversion of various image types)
- Ability to resize the splash window for your splash to fit

# Usage

## Extract all splashes
`nosplash EWSF.EWS --extract`

## Import your splash as bitmap
`nosplash EWSF.EWS -format bmp -in image.png -out OUT.EWS`

## Import your splash as jpeg
`nosplash EWSF.EWS -format jpeg -quality 95 -in image.png -out OUT.EWS`

# NosSplash
Simple script utility that allows you to extract and set custom splash inside EWSF.EWS

# Features
- Easy to install and use
- Support multiple image inputs (auto conversion of various image types)
- Ability to resize the splash window for your splash to fit

# Installation
`python -m pip install nosplash`

# Usage

## Extract all splashes
`python -m nosplash EWSF.EWS --extract`

## Minimal import
`python -m nosplash EWSF.EWS -in image.png`

## Import your splash as bitmap
`python -m nosplash EWSF.EWS -format bmp -in image.png -out OUT.EWS`

## Import your splash as jpeg
`python -m nosplash EWSF.EWS -format jpeg -quality 95 -in image.png -out OUT.EWS`

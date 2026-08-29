# Test Assets — Aegis Deepfake Detection API

## Synthetic assets (auto-generated, no download needed)

Run once before testing:
```bash
python scripts/generate_synthetic_assets.py
```

This creates:

| File | Purpose | Expected result |
|---|---|---|
| `real_face_synth.jpg` | Clear synthetic face | Quality gate PASS, low risk |
| `blurry_face_synth.jpg` | Heavily blurred face | Blur warning in response |
| `tiny_face_synth.jpg` | 40px face in large image | Resolution warning |
| `no_face_synth.jpg` | Car image, no face | `verdict: UNAVAILABLE` |
| `multi_face_synth.jpg` | Two faces side by side | Multi-face note in flags |
| `short_video_synth.mp4` | 5s synthetic video | Video pipeline runs |
| `compressed_video_synth.mp4` | Simulated WhatsApp compression | Use `X-Source-Hint: whatsapp` |

---

## Real test data (required for integration tests)

### Option A — Use your own training test splits

You already have these from training. Copy or symlink:

```
# From Doc 1 (image pipeline) — 140k dataset test split
cp $BASE_DIR/hdf5/test.h5 tests/assets/

# From Doc 2 (video pipeline) — FaceForensics++ test split
cp $BASE_DIR/hdf5_temporal/test_temporal.h5 tests/assets/
```

Extract individual images/videos from the HDF5 files using the helper script:
```bash
python scripts/extract_test_samples.py --count 10
```

### Option B — Public datasets (free, academic use)

#### Fake face images (GAN-generated)

**140k Real and Fake Faces** (your training dataset)
- Platform: Kaggle
- URL: https://www.kaggle.com/datasets/xhlulu/140k-real-and-fake-faces
- Size: ~1.4 GB
- What to download: Just `test/fake/` folder (10k images)
- Place in: `tests/assets/fake_faces/`

**This Face Does Not Exist** (StyleGAN2 live samples)
- URL: https://thispersondoesnotexist.com
- Grab 20–30 images manually (refresh for each)
- Place in: `tests/assets/fake_faces/`

#### Real face images

**LFW — Labeled Faces in the Wild**
- URL: http://vis-www.cs.umass.edu/lfw/lfw.tgz
- Size: 233 MB
- What to use: Any 50 images from `lfw/` directory
- Place in: `tests/assets/real_faces/`

**UTKFace**
- URL: https://www.kaggle.com/datasets/jangedoo/utkface-new
- Size: 290 MB (part 1 alone is sufficient)
- Place in: `tests/assets/real_faces/`

#### Fake face videos (deepfake)

**FaceForensics++ Test Set** (you already have this from training)
- Request access: https://github.com/ondyari/FaceForensics
- Your NB1 already processed these — use the videos from `test/` split
- Place in: `tests/assets/fake_videos/`

**DFDC Public Preview Dataset**
- URL: https://ai.facebook.com/datasets/dfdc/
- Requires: Facebook account + terms agreement (free)
- Size: Preview is ~10 GB
- Place mp4 files in: `tests/assets/fake_videos/`

**Celeb-DF v2**
- URL: https://github.com/yuezunli/celeb-deepfakeforensics
- Requires: Email request to authors (usually approved within 24h)
- Place in: `tests/assets/fake_videos/`

#### Real face videos

**VoxCeleb2** (real celebrity videos)
- URL: https://www.robots.ox.ac.uk/~vgg/data/voxceleb/vox2.html
- Large dataset — just download first few files (~1 GB)
- Place in: `tests/assets/real_videos/`

---

## Expected test results with real models

| Input | Expected verdict | Expected p_fake range |
|---|---|---|
| StyleGAN2 face (140k dataset) | FAKE / LIKELY_FAKE | 0.65 – 0.98 |
| LFW real face | REAL / LIKELY_REAL | 0.02 – 0.35 |
| FaceSwap video (FF++) | FAKE / LIKELY_FAKE | 0.60 – 0.95 |
| Face2Face video (FF++) | LIKELY_FAKE / FAKE | 0.55 – 0.90 |
| NeuralTextures video (FF++) | LIKELY_FAKE | 0.45 – 0.80 |
| Real VoxCeleb video | REAL / LIKELY_REAL | 0.05 – 0.35 |
| Stable Diffusion face | UNCERTAIN (blindspot) | 0.30 – 0.70 |
| Heavily compressed fake | LIKELY_FAKE | 0.40 – 0.75 |

---

## Edge cases to test manually

| Scenario | How to create | Expected behaviour |
|---|---|---|
| Face with sunglasses | Any selfie with glasses | Occlusion warning in flags |
| Portrait photo with 3+ people | Group selfie | Multi-face note, primary face analyzed |
| Profile view (90°) | Side-face photo | Detection may fail, `no_face_detected` possible |
| Screenshot of video call | Grab frame from Zoom | Quality gate may flag blur/compression |
| Video shorter than 2 seconds | `ffmpeg -t 1.5 input.mp4 output.mp4` | Temporal warning: < 2 sequences |
| 4K video | Any 4K source | Should work — faces extracted and resized |

---

## Model checkpoint paths

Set these in your `.env` file before running integration tests:

```env
# Image pipeline (from Doc 1 training)
IMAGE_EFFICIENTNET_PATH=models/image/efficientnet_best.pth
IMAGE_VIT_PATH=models/image/vit_best.pth
IMAGE_FREQCNN_PATH=models/image/freqcnn_best.pth
IMAGE_ENSEMBLE_CONFIG=models/image/ensemble_config.json

# Video pipeline (from Doc 2 training)
VIDEO_SPATIAL_PATH=models/video/spatial_best.pth
VIDEO_TEMPORAL_PATH=models/video/temporal_best.pth
VIDEO_FREQ_SRM_PATH=models/video/freq_srm_best.pth
```

Copy your trained `.pth` files to the `models/` directory before starting.

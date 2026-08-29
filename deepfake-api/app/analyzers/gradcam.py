"""
GradCAM heatmap generation for EfficientNet-B4.
Hooks the last convolutional block to produce a spatial activation map
showing WHICH facial regions triggered the deepfake classification.
"""
from __future__ import annotations

import base64
import io
import logging
from typing import Optional

import cv2
import numpy as np
import torch
import torch.nn as nn

logger = logging.getLogger(__name__)


class GradCAM:
    """
    Gradient-weighted Class Activation Mapping for a CNN.
    Registers forward and backward hooks on the target layer.
    """

    def __init__(self, model: nn.Module, target_layer: nn.Module):
        self.model = model
        self.gradients: Optional[torch.Tensor] = None
        self.activations: Optional[torch.Tensor] = None

        # Register hooks
        self._fwd_handle = target_layer.register_forward_hook(self._save_activation)
        self._bwd_handle = target_layer.register_full_backward_hook(self._save_gradient)

    def _save_activation(self, module, input, output):
        self.activations = output.detach()

    def _save_gradient(self, module, grad_input, grad_output):
        self.gradients = grad_output[0].detach()

    def generate(self, input_tensor: torch.Tensor) -> Optional[np.ndarray]:
        """
        Run forward+backward pass and produce a (H, W) heatmap in [0,1].
        input_tensor: (1, 3, 224, 224)
        """
        self.model.eval()
        input_tensor = input_tensor.requires_grad_(True)

        # Forward
        output = self.model(input_tensor)  # (1,) or (1,1)
        if output.dim() > 1:
            output = output.squeeze(1)
        score = output[0]

        # Backward
        self.model.zero_grad()
        score.backward()

        if self.gradients is None or self.activations is None:
            return None

        # Pool gradients across spatial dims → channel weights
        weights = self.gradients.mean(dim=(2, 3), keepdim=True)  # (1, C, 1, 1)

        # Weighted sum of activation maps
        cam = (weights * self.activations).sum(dim=1, keepdim=True)  # (1, 1, H, W)
        cam = torch.relu(cam).squeeze().cpu().numpy()                 # (H, W)

        # Normalize to [0, 1]
        if cam.max() > cam.min():
            cam = (cam - cam.min()) / (cam.max() - cam.min())
        else:
            cam = np.zeros_like(cam)

        return cam

    def remove_hooks(self):
        self._fwd_handle.remove()
        self._bwd_handle.remove()


def get_efficientnet_target_layer(model: nn.Module) -> Optional[nn.Module]:
    """
    Return the last convolutional block of EfficientNet-B4 backbone.
    This is the `blocks[-1]` of the backbone's conv_head or the last blocks entry.
    """
    try:
        backbone = model.backbone
        # timm EfficientNet: backbone.blocks is a Sequential of MBConv blocks
        if hasattr(backbone, "blocks"):
            return backbone.blocks[-1]
        # Fallback: conv_head
        if hasattr(backbone, "conv_head"):
            return backbone.conv_head
    except Exception as e:
        logger.warning(f"Could not find target layer: {e}")
    return None


def generate_gradcam_overlay(
    model: nn.Module,
    face_crop_bgr: np.ndarray,
    standard_tensor: torch.Tensor,
    device: str,
) -> Optional[str]:
    """
    Generate a GradCAM heatmap overlaid on the face image.
    Returns a base64-encoded JPEG string, or None on failure.

    face_crop_bgr: original BGR face crop for overlay
    standard_tensor: (1, 3, 224, 224) preprocessed tensor
    """
    target_layer = get_efficientnet_target_layer(model)
    if target_layer is None:
        logger.warning("GradCAM: no target layer found")
        return None

    gradcam = GradCAM(model, target_layer)
    try:
        tensor = standard_tensor.to(device)
        cam = gradcam.generate(tensor)
        if cam is None:
            return None

        # Resize cam to face crop size
        face_224 = cv2.resize(face_crop_bgr, (224, 224))
        cam_resized = cv2.resize(cam, (face_224.shape[1], face_224.shape[0]))

        # Apply colormap
        heatmap = cv2.applyColorMap(
            (cam_resized * 255).astype(np.uint8),
            cv2.COLORMAP_JET
        )

        # Overlay on original image (alpha blend)
        overlay = cv2.addWeighted(face_224, 0.5, heatmap, 0.5, 0)

        # Encode to base64
        _, buf = cv2.imencode(".jpg", overlay, [cv2.IMWRITE_JPEG_QUALITY, 90])
        b64 = base64.b64encode(buf.tobytes()).decode("utf-8")
        return f"data:image/jpeg;base64,{b64}"

    except Exception as e:
        logger.warning(f"GradCAM generation failed: {e}")
        return None
    finally:
        gradcam.remove_hooks()

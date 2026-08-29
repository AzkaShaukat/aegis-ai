"""
Minimal torch mock for test environments where PyTorch is not installed.
Loaded automatically by conftest.py before any app imports.
Covers exactly the torch API surface used by the Aegis Deepfake API.
"""
import sys
import types
import numpy as np


def _make_tensor(data, **kwargs):
    if isinstance(data, np.ndarray):
        return data.astype(np.float32)
    return np.array(data, dtype=np.float32)


class _Tensor(np.ndarray):
    """Thin numpy-backed tensor that supports .item(), .unsqueeze(), .squeeze()."""
    def item(self):
        return float(self.flat[0])

    def unsqueeze(self, dim):
        return np.expand_dims(self, axis=dim).view(_Tensor)

    def squeeze(self, dim=None):
        return np.squeeze(self, axis=dim).view(_Tensor) if dim is not None else np.squeeze(self).view(_Tensor)

    def to(self, *args, **kwargs):
        return self

    def view(self, *args):
        if len(args) == 1 and isinstance(args[0], type):
            return super().view(args[0])
        return self.reshape(args).view(_Tensor)

    def float(self):
        return self.astype(np.float32).view(_Tensor)


def tensor(data, dtype=None, **kwargs):
    arr = np.array(data, dtype=np.float32)
    return arr.view(_Tensor)


def zeros(*shape, **kwargs):
    s = shape[0] if len(shape) == 1 and isinstance(shape[0], (tuple, list)) else shape
    return np.zeros(s, dtype=np.float32).view(_Tensor)


def ones(*shape, **kwargs):
    s = shape[0] if len(shape) == 1 and isinstance(shape[0], (tuple, list)) else shape
    return np.ones(s, dtype=np.float32).view(_Tensor)


def from_numpy(arr):
    return arr.astype(np.float32).view(_Tensor)


def sigmoid(t):
    x = np.array(t, dtype=np.float64)
    return (1.0 / (1.0 + np.exp(-x))).view(_Tensor)


def cat(tensors, dim=0):
    return np.concatenate([np.array(t) for t in tensors], axis=dim).view(_Tensor)


def no_grad():
    class _ctx:
        def __enter__(self): return self
        def __exit__(self, *a): pass
        def __call__(self, fn):
            def wrapper(*a, **kw): return fn(*a, **kw)
            return wrapper
    return _ctx()


def load(path, map_location=None, weights_only=False):
    raise FileNotFoundError(f"Mock torch.load: file not found: {path}")


# ── nn mock ──────────────────────────────────────────────────────────────

class _Module:
    training = False
    def eval(self): return self
    def to(self, *a, **k): return self
    def parameters(self): return iter([])
    def __call__(self, *a, **k):
        return zeros(a[0].shape[0], 1)


class _Parameter(np.ndarray):
    def __new__(cls, data, requires_grad=True):
        obj = np.asarray(data, dtype=np.float32).view(cls)
        obj.requires_grad = requires_grad
        return obj


class _Sequential(_Module):
    def __init__(self, *layers): self.layers = layers
    def __call__(self, x):
        for layer in self.layers:
            x = layer(x) if callable(layer) else x
        return x


class _Linear(_Module):
    def __init__(self, in_f, out_f, bias=True):
        self.weight = zeros(out_f, in_f)
        self.bias = zeros(out_f) if bias else None
    def __call__(self, x):
        x = np.array(x, dtype=np.float32)
        out = x @ np.array(self.weight).T
        if self.bias is not None:
            out += np.array(self.bias)
        return out.view(_Tensor)


class _LayerNorm(_Module):
    def __init__(self, *a, **k): pass
    def __call__(self, x): return x


class _Dropout(_Module):
    def __init__(self, p=0.5): pass
    def __call__(self, x): return x


class _BatchNorm1d(_Module):
    def __init__(self, *a, **k): pass
    def __call__(self, x): return x


class _BatchNorm2d(_Module):
    def __init__(self, *a, **k): pass
    def __call__(self, x): return x


class _ReLU(_Module):
    def __call__(self, x): return np.maximum(0, x).view(_Tensor)


class _GELU(_Module):
    def __call__(self, x):
        x = np.array(x, dtype=np.float64)
        return (x * 0.5 * (1.0 + np.tanh(np.sqrt(2/np.pi) * (x + 0.044715*x**3)))).astype(np.float32).view(_Tensor)


class _SiLU(_Module):
    def __call__(self, x):
        x = np.array(x, dtype=np.float32)
        return (x / (1 + np.exp(-x))).view(_Tensor)


class _AdaptiveAvgPool2d(_Module):
    def __init__(self, output_size): self.output_size = output_size
    def __call__(self, x): return zeros(x.shape[0], x.shape[1], 1, 1)


class _Flatten(_Module):
    def __call__(self, x):
        x = np.array(x)
        return x.reshape(x.shape[0], -1).view(_Tensor)


class _Conv2d(_Module):
    def __init__(self, in_c, out_c, kernel_size, stride=1, padding=0,
                 groups=1, bias=True, **k):
        self.out_c = out_c
        self.weight = _Parameter(zeros(out_c, in_c // groups, kernel_size if isinstance(kernel_size,int) else kernel_size[0], kernel_size if isinstance(kernel_size,int) else kernel_size[0]))
    def __call__(self, x):
        b = x.shape[0] if hasattr(x, 'shape') else 1
        h = x.shape[2] if hasattr(x, 'shape') and len(x.shape) > 2 else 1
        w = x.shape[3] if hasattr(x, 'shape') and len(x.shape) > 3 else 1
        return zeros(b, self.out_c, h, w)


class _Identity(_Module):
    def __call__(self, x): return x


class _TransformerEncoderLayer(_Module):
    def __init__(self, *a, **k): pass
    def __call__(self, x, *a, **k): return x


class _TransformerEncoder(_Module):
    def __init__(self, layer, num_layers): pass
    def __call__(self, x, *a, **k): return x


def _init_xavier_uniform_(w): pass
def _init_zeros_(b): pass
def _init_trunc_normal_(t, std=0.02): pass


class _nn_init:
    xavier_uniform_ = staticmethod(_init_xavier_uniform_)
    zeros_ = staticmethod(_init_zeros_)
    trunc_normal_ = staticmethod(_init_trunc_normal_)


class _nn:
    Module = _Module
    Parameter = _Parameter
    Sequential = _Sequential
    Linear = _Linear
    LayerNorm = _LayerNorm
    Dropout = _Dropout
    BatchNorm1d = _BatchNorm1d
    BatchNorm2d = _BatchNorm2d
    ReLU = _ReLU
    GELU = _GELU
    SiLU = _SiLU
    AdaptiveAvgPool2d = _AdaptiveAvgPool2d
    Flatten = _Flatten
    Conv2d = _Conv2d
    Identity = _Identity
    TransformerEncoderLayer = _TransformerEncoderLayer
    TransformerEncoder = _TransformerEncoder
    init = _nn_init()


class _cuda:
    @staticmethod
    def is_available(): return False
    class amp:
        @staticmethod
        def autocast(): pass


# ── Assemble mock torch module ────────────────────────────────────────────

torch_mock = types.ModuleType("torch")
torch_mock.Tensor = _Tensor
torch_mock.tensor = tensor
torch_mock.zeros = zeros
torch_mock.ones = ones
torch_mock.from_numpy = from_numpy
torch_mock.sigmoid = sigmoid
torch_mock.cat = cat
torch_mock.no_grad = no_grad
torch_mock.load = load
torch_mock.nn = _nn()
torch_mock.cuda = _cuda()
torch_mock.float32 = np.float32
torch_mock.float64 = np.float64

sys.modules["torch"] = torch_mock
sys.modules["torch.nn"] = torch_mock.nn
sys.modules["timm"] = types.ModuleType("timm")  # stub — not used in unit tests

# Stub timm.create_model
def _stub_create_model(name, pretrained=False, num_classes=0):
    m = _Module()
    m.num_features = 1408 if "b2" in name else (1792 if "b4" in name else 768)
    return m

import sys
sys.modules["timm"].create_model = _stub_create_model

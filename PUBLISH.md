# Publishing to PyPI

## Prerequisites

```powershell
pip install build twine
```

## Build

```powershell
python -m build
```

## Publish to PyPI

```powershell
twine upload dist/*
```

You'll need a PyPI API token. Set it via:

```powershell
$env:PYPI_API_TOKEN = "pypi-..."
twine upload -u __token__ -p $env:PYPI_API_TOKEN dist/*
```

## Version Bumps

### Patch (bug fix)
```powershell
# Update version in pyproject.toml: 0.1.0 -> 0.1.1
python -m build
twine upload dist/*
```

### Minor (new feature)
```powershell
# Update version in pyproject.toml: 0.1.0 -> 0.2.0
python -m build
twine upload dist/*
```

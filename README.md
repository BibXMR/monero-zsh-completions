# monero-zsh-completions

Zsh tab-completions for all 14 [Monero](https://github.com/monero-project/monero) CLI tools.

Sourced directly from the Monero C++ codebase.

## Install

### Manual

Clone the repo and add its path to your `fpath` before `compinit` in your `~/.zshrc`:

```zsh
git clone https://github.com/BibXMR/monero-zsh-completions.git ~/.zsh/monero-zsh-completions
```

```zsh
# ~/.zshrc
fpath=(~/.zsh/monero-zsh-completions $fpath)
autoload -Uz compinit && compinit
```

Then restart your shell or run `source ~/.zshrc`.

### Oh My Zsh

Clone into the Oh My Zsh custom plugins directory:

```zsh
git clone https://github.com/BibXMR/monero-zsh-completions.git \
  ${ZSH_CUSTOM:-~/.oh-my-zsh/custom}/plugins/monero-zsh-completions
```

Add it to your plugin list in `~/.zshrc`:

```zsh
plugins=(... monero-zsh-completions)
```

Restart your shell or run `source ~/.zshrc`.

### Zinit

```zsh
zinit light BibXMR/monero-zsh-completions
```

### Antidote

Add to your `.zsh_plugins.txt`:

```
BibXMR/monero-zsh-completions
```

### zplug

```zsh
zplug "BibXMR/monero-zsh-completions"
```

### Homebrew (macOS / Linuxbrew)

If you have a Homebrew-managed zsh, you can symlink directly:

```zsh
for f in /path/to/monero-zsh-completions/_monero*; do
  ln -sf "$f" "$(brew --prefix)/share/zsh/site-functions/$(basename "$f")"
done
autoload -Uz compinit && compinit
```

### System-wide

Copy the completion files to a directory already in your `fpath`:

```zsh
sudo cp _monero* /usr/local/share/zsh/site-functions/
autoload -Uz compinit && compinit
```

## Example Usage

```
monerod --<TAB>           # shows all options with descriptions
monerod --data-dir <TAB>  # completes directories
monerod --config-file <TAB>  # completes file paths
monerod --check-updates <TAB>  # shows: disabled notify download update
monerod --rpc-ssl <TAB>      # shows: enabled disabled autodetect
monerod sta<TAB>              # completes to status
```

## Updating

Completions were generated from the Monero source tree. If new options are added upstream, the completion files for any of the 14 tools may need updating. Pull requests are welcome.

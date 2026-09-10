package cli

import (
	"fmt"
	"strings"
)

func runCompletion(args []string) error {
	if len(args) != 1 {
		return fmt.Errorf("usage: taildoc completion <bash|zsh|fish>")
	}
	var script string
	switch args[0] {
	case "bash":
		script = bashCompletion
	case "zsh":
		script = zshCompletion
	case "fish":
		script = fishCompletion
	default:
		return fmt.Errorf("unknown shell %q (want bash, zsh, or fish)", args[0])
	}
	fmt.Print(strings.TrimSpace(script) + "\n")
	return nil
}

const bashCompletion = `# taildoc shell completion for bash
_taildoc() {
  local cur="${COMP_WORDS[COMP_CWORD]}" command="${COMP_WORDS[1]}"
  local commands="auth inventory audit explain find show snapshot diff graph history ui doctor watch completion help version"
  case "$command" in
    auth) COMPREPLY=( $(compgen -W "login status logout" -- "$cur") ) ;;
    completion) COMPREPLY=( $(compgen -W "bash zsh fish" -- "$cur") ) ;;
    audit) COMPREPLY=( $(compgen -W "--output --fail-on --snapshot" -- "$cur") ) ;;
    find|show) COMPREPLY=( $(compgen -W "--snapshot" -- "$cur") ) ;;
    graph) COMPREPLY=( $(compgen -W "--format --output --snapshot" -- "$cur") ) ;;
    history) COMPREPLY=( $(compgen -W "--db --record" -- "$cur") ) ;;
    ui) COMPREPLY=( $(compgen -W "--snapshot" -- "$cur") ) ;;
    doctor) COMPREPLY=( $(compgen -W "--check-api --collect" -- "$cur") ) ;;
    watch) COMPREPLY=( $(compgen -W "--interval --once" -- "$cur") ) ;;
    snapshot) COMPREPLY=( $(compgen -W "--output" -- "$cur") ) ;;
    *) COMPREPLY=( $(compgen -W "$commands" -- "$cur") ) ;;
  esac
}
complete -F _taildoc taildoc`

const zshCompletion = `#compdef taildoc
_taildoc() {
  local -a commands
  commands=(
    'auth:connect to a tailnet'
    'inventory:show tailnet inventory'
    'audit:analyze tailnet configuration'
    'explain:explain a policy path'
    'find:search tailnet resources'
    'show:show resource details'
    'snapshot:save a snapshot'
    'diff:compare snapshots'
    'graph:render grant relationships'
    'history:show finding history'
    'ui:open terminal dashboard'
    'doctor:check local setup and API readiness'
    'watch:follow inventory changes'
    'completion:generate shell completion'
    'help:show help'
    'version:show version'
  )
  if (( CURRENT == 2 )); then
    _describe -t commands 'taildoc command' commands
    return
  fi
  case $words[2] in
    auth) _values 'auth command' login status logout ;;
    completion) _values 'shell' bash zsh fish ;;
    audit) _arguments '--output[format]:format:(text json sarif markdown)' '--fail-on[severity]:severity:(info low medium high)' '--snapshot[snapshot file]:file:_files' ;;
    find|show|ui) _arguments '--snapshot[snapshot file]:file:_files' ;;
    graph) _arguments '--format[format]:format:(mermaid dot)' '--output[output file]:file:_files' '--snapshot[snapshot file]:file:_files' ;;
    snapshot) _arguments '--output[output file]:file:_files' ;;
    history) _arguments '--db[database path]:file:_files' '--record[record audit]' ;;
    doctor) _arguments '--check-api[verify credentials with API]' '--collect[exercise live collection]' ;;
    watch) _arguments '--interval[refresh interval]:duration:' '--once[print baseline and exit]' ;;
  esac
}
_taildoc "$@"`

const fishCompletion = `# taildoc shell completion for fish
complete -c taildoc -f
complete -c taildoc -n '__fish_use_subcommand' -a 'auth inventory audit explain find show snapshot diff graph history ui doctor watch completion help version'
complete -c taildoc -n '__fish_seen_subcommand_from auth' -a 'login status logout'
complete -c taildoc -n '__fish_seen_subcommand_from completion' -a 'bash zsh fish'
complete -c taildoc -n '__fish_seen_subcommand_from audit' -l output -a 'text json sarif markdown'
complete -c taildoc -n '__fish_seen_subcommand_from audit' -l fail-on -a 'info low medium high'
complete -c taildoc -n '__fish_seen_subcommand_from audit find show graph ui' -l snapshot -r
complete -c taildoc -n '__fish_seen_subcommand_from graph' -l format -a 'mermaid dot'
complete -c taildoc -n '__fish_seen_subcommand_from graph snapshot' -l output -r
complete -c taildoc -n '__fish_seen_subcommand_from history' -l db -r
complete -c taildoc -n '__fish_seen_subcommand_from history' -l record
complete -c taildoc -n '__fish_seen_subcommand_from doctor' -l check-api
complete -c taildoc -n '__fish_seen_subcommand_from doctor' -l collect
complete -c taildoc -n '__fish_seen_subcommand_from watch' -l interval -r
complete -c taildoc -n '__fish_seen_subcommand_from watch' -l once
`

/** What the guard does with a command it judges dangerous (the `mode` setting). */
export type ShellGuardMode = 'deny' | 'ask'

declare module 'claude-code' {
  interface PluginState {
    'shell-guard': {
      /** True after `/shell-guard off`, until `/shell-guard on` or the session ends. */
      isOff: boolean
    }
  }
}

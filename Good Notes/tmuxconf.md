```bash
# -----------------------------------------------------------------------------
# Tmux 基本配置 - 要求 Tmux >= 2.3
# 如果不想使用插件，只需要将此节的内容写入 ~/.tmux.conf 即可
# -----------------------------------------------------------------------------

# C-b 和 VIM 冲突，修改 Prefix 组合键为 Control-Z，按键距离近
set -g prefix C-z

set -g base-index         1     # 窗口编号从 1 开始计数
set -g display-panes-time 10000 # PREFIX-Q 显示编号的驻留时长，单位 ms
set -g mouse              on    # 开启鼠标
set -g pane-base-index    1     # 窗格编号从 1 开始计数
set -g renumber-windows   on    # 关掉某个窗口后，编号重排

setw -g allow-rename      off   # 禁止活动进程修改窗口名
setw -g automatic-rename  off   # 禁止自动命名新窗口
setw -g mode-keys         vi    # 进入复制模式的时候使用 vi 键位（默认是 EMACS）

set -g status-interval 1    # 状态栏刷新时间(右下角秒针会跳动)
set -g status-justify left  # 状态栏窗口列表(window list)左对齐

set -g visual-activity on # 启用活动警告
set -g message-style "bg=#202529, fg=#91A8BA" # 指定消息通知的前景、后景色


# 右下角类似效果：21:58:48 12-12
# set -g status-right "%H:%M:%S %d-%b"

# 设置整个状态栏背景颜色 bg(背景色) fg(前景色)
set -g status-style "bg=#882244"


# run-shell "ifconfig tun0 | grep 'inet ' | cut  -d ' ' -f 10"
# run-shell "tmux display-message -p '$(curl -s http://whatismyip.akamai.com/)'"

set-option -g status-right "#[fg=green]#(ifconfig tun0 | grep 'inet ' | cut  -d ' ' -f 10)"

```


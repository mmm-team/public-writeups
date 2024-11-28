#!/bin/bash

tmux new-session -s solve_chal \; \
    split-window -h \; \
    split-window -v \; \
    send-keys -t solve_chal:0.0 "ngrok http 8001" C-m \; \
    send-keys -t solve_chal:0.1 "cd attack && python3 -m http.server 8001" C-m \; \
    send-keys -t solve_chal:0.2 "python3 script.py" C-m

# ngrok is a placeholder here and does not actually work because it'll auto redirect to https
# i used a cloudflare tunnel instead
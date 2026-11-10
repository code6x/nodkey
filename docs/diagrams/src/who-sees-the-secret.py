# Who sees the secret: the source of docs/diagrams/who-sees-the-secret.svg
# and .png. Render it with a Schemdraw run that sets DRAW_OUT to the output
# path, for example: DRAW_OUT=out.svg python3 who-sees-the-secret.py
import os

import schemdraw
from schemdraw import flow

schemdraw.config(fontsize=12)

W, H = 4.4, 2.6   # the size of a box
GAP = 5.0         # the space between two boxes

with schemdraw.Drawing(show=False) as d:
    agent = flow.Box(w=W, h=H).at((0, 0)).anchor('center').label(
        'Agent (chat)\n\nnodkey puts\nno value here')
    cmd = flow.Box(w=W + 0.6, h=H).at((W + GAP + 0.3, 0)).anchor('center').label(
        'nodkey client\n+ the command\n\na bad command\ncan print it')
    broker = flow.Box(w=W, h=H).at((2 * (W + GAP) + 0.6, 0)).anchor('center').label(
        'Broker\n\nkeys and\nstore access')
    phone = flow.Box(w=W - 0.6, h=H).at((3 * (W + GAP) + 0.3, 0)).anchor('center').label(
        'Your phone\n\nyou read the\ncommand and tap')

    up, dn = 0.45, -0.45
    flow.Arrow().at((agent.E.x, up)).to((cmd.W.x, up)).label('1. writes\nthe command', 'top')
    flow.Arrow().at((cmd.W.x, dn)).to((agent.E.x, dn)).label('6. output only', 'bottom')
    flow.Arrow().at((cmd.E.x, up)).to((broker.W.x, up)).label('2. asks', 'top')
    flow.Arrow().at((broker.W.x, dn)).to((cmd.E.x, dn)).label(
        '5. the value, only into\nthe command\'s environment', 'bottom')
    flow.Arrow().at((broker.E.x, up)).to((phone.W.x, up)).label('3. asks you', 'top')
    flow.Arrow().at((phone.W.x, dn)).to((broker.E.x, dn)).label('4. Approve', 'bottom')

    # SSH: the key stays on the broker; the client gets only a signature.
    y = -H / 2 - 1.6
    flow.Line().at(broker.S).to((broker.S.x, y))
    flow.Arrow().at((broker.S.x, y)).to((cmd.S.x, y)).label(
        'SSH: a signature only, the key stays on the broker', 'bottom')
    flow.Arrow().at((cmd.S.x, y)).to(cmd.S)

    d.save(os.environ['DRAW_OUT'])

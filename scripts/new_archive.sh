#!/bin/sh
find . -iname script/*.606843546 |grep script/ |xargs decryptArcTool c ~/$1.arc

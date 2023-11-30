rm netTool
gcc main.c -lpcap -o netTool -g
sudo ./netTool -findprinters
cp netTool nToolBG
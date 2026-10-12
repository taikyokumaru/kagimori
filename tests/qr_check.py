import json, sys, numpy as np, cv2
data = json.load(open(sys.argv[1]))
bad = 0
for c in data:
    s = c['size']; q = 4
    img = np.full(((s + 2*q) * 8, (s + 2*q) * 8), 255, np.uint8)
    for y, row in enumerate(c['m']):
        for x, ch in enumerate(row):
            if ch == '1':
                img[(y+q)*8:(y+q+1)*8, (x+q)*8:(x+q+1)*8] = 0
    det = cv2.QRCodeDetector()
    got, pts, _ = det.detectAndDecode(img)
    ok = got == c['text']
    if not ok:
        bad += 1
    print('OK ' if ok else 'NG ', 'v%-2d %s len=%d' % (c['version'], c['ecc'], len(c['text'].encode())))
print('failures:', bad, 'of', len(data))
sys.exit(1 if bad else 0)

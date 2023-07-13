# boomstream-downloader
Download videos from boomstream

## Usage
```bash
node index.js <url-format> <key> <iv> <start> <end> <output-file-path>
```

I haven't found a way to automatically get key and initialization vector for decryption yet. So it requires to do it manually by putting break points in your browser.
For example,
```bash
node ./index.js https://cdnv-m6.boomstream.com/vod/hash:1355bd284c6a399bd599d240bf88945f/id:35105.29443.830629.43032706.150106.hls/time:0/data:eyJ1c2VfZGlyZWN0X2xpbmtzIjoieWVzIiwiaXNfZW5jcnlwdCI6InllcyJ9/m54/2023/02/21/TxktkADe.mp4/media-{0}.ts 486e4b785a7030365370735a49575037 4d30703057514c393136443450444541 0 647 out.ts
```

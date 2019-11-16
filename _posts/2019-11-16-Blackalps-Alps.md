---
layout: post
title: Blackalps 2019 - Alps
---

This challenge is about steganography. The goal is to extract the flag from an image. However, the flag is hidden in a Javascript, which is part of a hidden PDF that first needs to be extracted from the image.

<!--more-->
## Description

*DESCRIPTION MISSING*

*--> Find the Flag within the image ><--*


## Solution
Initially, I started with getting some information about the image using `exiftool`. Unfortunately, it did not have anything interesting there.

```bash
root@kali:~/Documents/ctf/blackalps_19/forensics/alps# exiftool favicon.jpg 
ExifTool Version Number         : 11.74
File Name                       : favicon.jpg
Directory                       : .
File Size                       : 43 kB
File Modification Date/Time     : 2019:11:08 18:21:55+01:00
File Access Date/Time           : 2019:11:15 17:16:53+01:00
File Inode Change Date/Time     : 2019:11:15 17:16:51+01:00
File Permissions                : rw-r--r--
File Type                       : JPEG
File Type Extension             : jpg
MIME Type                       : image/jpeg
JFIF Version                    : 1.01
Resolution Unit                 : inches
X Resolution                    : 95
Y Resolution                    : 95
Image Width                     : 32
Image Height                    : 32
Encoding Process                : Progressive DCT, Huffman coding
Bits Per Sample                 : 8
Color Components                : 3
Y Cb Cr Sub Sampling            : YCbCr4:4:4 (1 1)
Image Size                      : 32x32
Megapixels                      : 0.001
```

As a next step, I thought there might be something stored within the image itself, so I used `binwalk` to examine the contents of the image.

```bash
root@kali:~/Documents/ctf/blackalps_19/forensics/alps# binwalk favicon.jpg 

DECIMAL       HEXADECIMAL     DESCRIPTION
--------------------------------------------------------------------------------
0             0x0             JPEG image data, JFIF standard 1.01
931           0x3A3           PDF document, version: "1.4"
1002          0x3EA           Zlib compressed data, default compression
1754          0x6DA           Zlib compressed data, default compression
2064          0x810           Zlib compressed data, default compression
8751          0x222F          Zlib compressed data, default compression
9327          0x246F          Zlib compressed data, default compression
22361         0x5759          Zlib compressed data, default compression
23155         0x5A73          Zlib compressed data, default compression
32368         0x7E70          Zlib compressed data, default compression
38285         0x958D          Zlib compressed data, default compression
41495         0xA217          Zlib compressed data, default compression
42727         0xA6E7          Zlib compressed data, default compression

```

Surprisingly, there is a hidden PDF file within the image. Extracting it with `binwalk -D pdf` and viewing it did not reveal much information. 

![Hidden PDF](/resources/2019/blackalps/images/hidden_pdf.png)

On the other side, it has a very suspicious title `L7'/qNJV[aiUm'vvU\kv[U^r)UM:|vns`. So lets have a closer look at this PDF and see if it has any dynamic content like Javascript, which can be extracted with `pdfinfo -js extracted.pdf`, where *extracted.pdf* is the extracted PDF file. The PDF contains the following Javascript.

```javascript
function wtf(pwd){
  return (function(x){return x.join('');})((function(x){return x.split('');})(pwd).map(function(x){return x.charCodeAt(0);}).map(function(y){return ((function(x){return String.fromCharCode(x);})((function(x){return y + x;})((function(x){return x * 10;})((function(x){return (-1)**x;})((function(x){return x % 2;})(y))))))}))
}

var pwd = this.getField("InPassword").value;
if (pwd != null && pwd.length > 0){
        if (wtf(pwd) == this.info.Title){
                app.alert("0.o You actually did it !");
        }
        else{
                app.alert("Haha nope");
        }
}
else{
        app.alert("Haha nope");
}
```

Based on this Javascript, it seems like `0.o You actually did it !` in case when the result of `wtf()` with some input as argument is equal to the previously mentioned title of the PDF. I am guessing that the input will be the flag, so I tried to run the function with some part of the flag which is known, namely `BA19{`. The result of `wtf('BA19{')` is `L7'/q` which is exactly the beginning of the PDF's title, so my assumption is probably right. So it seems to be some kind of substitution cipher. What is unknown so far is if the function is a 1-to-1 mapping or not, so I duplicated the input to check if the output is also duplicated. And indeed, `wtf(BA19{BA19{) = L7'/qL7'/q`. Therefore, the next step is to find the exact mapping by running `wtf()` with a set of characters. After I got the mapping, I run the following python script to decode the flag.

```python
# basic alphabet
chars  = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789#|{}_/@$"

# wtf(chars) - some unicode character are replaced with *
mapped = "WlYn[p]r_tavcxezg|i~k*m*o*7L9N;P=R?TAVCXEZG\I^K`MbOd:'<)>+@-B/**qsU%J."

title  = "L7'/qNJV[aiUm'vvU\kv[U^r)UM:|vns"

flag = ""

for i in title:
    flag += chars[mapped.index(i)]

print(flag)
```

The printed flag is: **BA19{D@Leks_w1ll_Rule_Th3_W0rld}**



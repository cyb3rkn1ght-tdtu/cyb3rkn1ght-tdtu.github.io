const fs = require('fs');
const path = require('path');

const srcDir = '/home/caterpie/Writeups/Junior.Crypt.2026';
const destFile = '/home/caterpie/WebCB9v2/content/writeups/junior-crypt-2026.md';
const destImagesDir = '/home/caterpie/WebCB9v2/content/images/writeup';

// Ensure destinations exist
if (!fs.existsSync(path.dirname(destFile))) fs.mkdirSync(path.dirname(destFile), { recursive: true });
if (!fs.existsSync(destImagesDir)) fs.mkdirSync(destImagesDir, { recursive: true });

function copyFolderSync(from, to) {
  if (!fs.existsSync(to)) fs.mkdirSync(to, { recursive: true });
  fs.readdirSync(from).forEach(element => {
    if (fs.lstatSync(path.join(from, element)).isFile()) {
      fs.copyFileSync(path.join(from, element), path.join(to, element));
    } else {
      copyFolderSync(path.join(from, element), path.join(to, element));
    }
  });
}

// Group files by category
const categories = {};
fs.readdirSync(srcDir).forEach(dir => {
  const catPath = path.join(srcDir, dir);
  if (fs.statSync(catPath).isDirectory() && dir !== '.git') {
    const mdFiles = [];
    fs.readdirSync(catPath).forEach(file => {
      if (file.endsWith('.md') && file.toLowerCase() !== 'readme.md') {
        mdFiles.push(path.join(catPath, file));
      }
    });
    if (mdFiles.length > 0) {
      mdFiles.sort();
      categories[dir] = mdFiles;
    }
    
    // Copy images if they exist
    const imgDir = path.join(catPath, 'images');
    if (fs.existsSync(imgDir)) {
      const catSlug = dir.toLowerCase().replace(/[^a-z0-9]+/g, '-');
      copyFolderSync(imgDir, path.join(destImagesDir, catSlug));
    }
  }
});

const frontmatter = `---
title: "Junior Crypt 2026 Writeups"
date: "2026.07.21"
author: "Cyberknight"
categoryEn: "CTF"
categoryJp: "連載"
difficulty: "hard"
---
# Tổng kết Junior Crypt 2026 — Team cyb3rkn1ght.tdtu

## Thông tin giải đấu
- **Giải:** Junior Crypt 2026
- **Hình thức:** Jeopardy
- **Thời gian:** N/A

## Kết quả của team
| Hạng mục | Kết quả |
|---|---|
| Team | **cyb3rkn1ght.tdtu** |
| Điểm số | **N/A** pts |
| Challenge đã giải | **35 / ?** |

---

`;

let content = frontmatter;

for (const [cat, files] of Object.entries(categories)) {
  const catName = cat.replace(/_/g, ' ');
  content += `\n# ${catName}\n\n`;
  
  for (const file of files) {
    let fileContent = fs.readFileSync(file, 'utf8');
    
    // Clean frontmatter
    if (fileContent.startsWith('---')) {
      const endOfFm = fileContent.indexOf('---', 3);
      if (endOfFm !== -1) {
        fileContent = fileContent.substring(endOfFm + 3).trim();
      }
    } else if (fileContent.startsWith('+++')) {
      const endOfFm = fileContent.indexOf('+++', 3);
      if (endOfFm !== -1) {
        fileContent = fileContent.substring(endOfFm + 3).trim();
      }
    }

    const basename = path.basename(file, '.md');
    let chalName = '';
    
    let m = fileContent.match(/^title:\s*["'](.*?)["']\s*$/m);
    if (m) chalName = m[1].trim();
    else {
      m = fileContent.match(/^title\s*=\s*["'](.*?)["']\s*$/m);
      if (m) chalName = m[1].trim();
      else {
        m = fileContent.match(/^\*\s*Challenge:\s*(.+)$/m);
        if (m) chalName = m[1].trim();
        else {
          m = fileContent.match(/^Challenge:\s*(.+)$/m);
          if (m) chalName = m[1].trim();
          else {
            m = fileContent.match(/^#\s+(.+)$/m);
            if (m && !/^(1\.|Thông tin|Phân tích|Đề bài|Solution|Challenge info)/i.test(m[1].trim())) {
              chalName = m[1].trim();
            } else {
              chalName = basename.replace(/-/g, ' ');
            }
          }
        }
      }
    }

    // Try to remove the H1 if it's identical or very similar to the extracted chalName
    // Or just remove the first H1 if it's the challenge title
    const firstH1 = fileContent.match(/^#\s+(.+)$/m);
    if (firstH1 && (firstH1[1].trim() === chalName || !/^(1\.|Thông tin|Phân tích|Đề bài|Solution|Challenge info)/i.test(firstH1[1].trim()))) {
      fileContent = fileContent.replace(/^#\s+.+$/m, '').trim();
    }
    
    // Clean up "Write-up", "CTF Writeup", etc. from challenge name
    chalName = chalName.replace(/[:—-]?\s*(?:\bctf\b)?\s*write[- ]?up\s*[:-]?/gi, '').trim();
    // Clean up tags like "[Grodno CTF]", "Rev002:", and category suffixes like "(Pwn)"
    chalName = chalName.replace(/^(?:\[.*?\]\s*|Rev\d+:\s*)/i, '');
    chalName = chalName.replace(/\s*\([^)]+\)$/, '');
    // Sometimes it might leave a trailing hyphen if the format was strange
    chalName = chalName.replace(/^[-—:\s]+|[-—:\s]+$/g, '');
    
    // Downgrade all other headings so they are AT LEAST ###, but DO NOT touch code blocks
    const blocks = fileContent.split('```');
    for (let i = 0; i < blocks.length; i += 2) {
      blocks[i] = blocks[i].replace(/^(#+)/gm, (match) => '#'.repeat(Math.max(3, match.length + 1)));
    }
    fileContent = blocks.join('```');

    const catSlug = cat.toLowerCase().replace(/[^a-z0-9]+/g, '-');
    
    // Fix image paths: images/pic.png -> images/<catSlug>/pic.png
    // and ./images/pic.png -> images/<catSlug>/pic.png
    fileContent = fileContent.replace(/(!\[.*?\]\()(\.\/)?images\//g, `$1../images/writeup/${catSlug}/`);

    content += `## ${chalName}\n\n${fileContent}\n\n`;
  }
}

fs.writeFileSync(destFile, content);
console.log('Merged writeups into ' + destFile);

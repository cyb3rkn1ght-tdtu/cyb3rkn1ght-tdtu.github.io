const fs = require('fs');
const path = require('path');

const srcDir = '/home/caterpie/Writeups/Junior.Crypt.2026';
const destDir = '/home/caterpie/WebCB9v2/content/writeups';

if (!fs.existsSync(destDir)) fs.mkdirSync(destDir, { recursive: true });

function walkDir(dir) {
  let results = [];
  const list = fs.readdirSync(dir);
  list.forEach(file => {
    const filePath = path.join(dir, file);
    const stat = fs.statSync(filePath);
    if (stat && stat.isDirectory()) {
      results = results.concat(walkDir(filePath));
    } else {
      if (filePath.endsWith('.md')) results.push(filePath);
    }
  });
  return results;
}

const files = walkDir(srcDir);

let count = 0;
for (const file of files) {
  const content = fs.readFileSync(file, 'utf8');
  if (content.startsWith('---')) {
    // Already has frontmatter
    continue;
  }
  
  const basename = path.basename(file, '.md');
  const dirname = path.basename(path.dirname(file)); // category
  
  let catEn = 'WEB';
  let catJp = 'アクション';
  let title = basename;
  
  // Try to extract title from first # heading
  const match = content.match(/^#\s+(.+)$/m);
  if (match) {
    title = match[1].trim();
  } else {
    title = title.replace(/-/g, ' ');
  }

  if (dirname.toLowerCase().includes('crypto')) {
    catEn = 'CRYPTO';
    catJp = '暗号';
  } else if (dirname.toLowerCase().includes('pwn')) {
    catEn = 'PWN';
    catJp = '制圧';
  } else if (dirname.toLowerCase().includes('rev')) {
    catEn = 'REV';
    catJp = '解析';
  } else if (dirname.toLowerCase().includes('forensic')) {
    catEn = 'FORENSICS';
    catJp = '鑑識';
  } else if (dirname.toLowerCase().includes('osint')) {
    catEn = 'OSINT';
    catJp = '諜報';
  }

  const frontmatter = `---
title: "${title.replace(/"/g, '\\"')}"
date: "2026.07.21"
author: "admin"
categoryEn: "${catEn}"
categoryJp: "${catJp}"
difficulty: "mid"
---
`;

  const newContent = frontmatter + content;
  fs.writeFileSync(path.join(destDir, basename + '.md'), newContent);
  count++;
}

console.log(`Imported ${count} writeups.`);

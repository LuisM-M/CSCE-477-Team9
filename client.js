const http = require('http');
const crypto = require('crypto');

// Function to make HTTP requests
function makeRequest(method, path, data = null) {
  return new Promise((resolve, reject) => {
    const options = {
      hostname: 'localhost',
      port: 3000,
      path: path,
      method: method,
      headers: {
        'Content-Type': 'application/json'
      }
    };

    const req = http.request(options, (res) => {
      let body = '';
      
      res.on('data', (chunk) => {
        body += chunk;
      });
      
      res.on('end', () => {
        try {
          resolve(JSON.parse(body));
        } catch (e) {
          resolve(body);
        }
      });
    });

    req.on('error', (e) => {
      reject(e);
    });

    if (data) {
      req.write(JSON.stringify(data));
    }
    
    req.end();
  });
}

// AES-256-GCM encryption
function encryptAES(text, key) {
  const iv = crypto.randomBytes(16);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  
  let encrypted = cipher.update(text, 'utf8', 'hex');
  encrypted += cipher.final('hex');
  
  const authTag = cipher.getAuthTag();
  
  return {
    encrypted,
    iv: iv.toString('hex'),
    authTag: authTag.toString('hex')
  };
}

// AES-256-GCM decryption
function decryptAES(encryptedData, key) {
  const decipher = crypto.createDecipheriv(
    'aes-256-gcm',
    key,
    Buffer.from(encryptedData.iv, 'hex')
  );
  
  decipher.setAuthTag(Buffer.from(encryptedData.authTag, 'hex'));
  
  let decrypted = decipher.update(encryptedData.encrypted, 'hex', 'utf8');
  decrypted += decipher.final('utf8');
  
  return decrypted;
}

// ChaCha20-Poly1305 encryption
function encryptChaCha20(text, key) {
  const iv = crypto.randomBytes(12); // ChaCha20 uses 12-byte nonce
  const cipher = crypto.createCipheriv('chacha20-poly1305', key, iv, {
    authTagLength: 16
  });
  
  let encrypted = cipher.update(text, 'utf8', 'hex');
  encrypted += cipher.final('hex');
  
  const authTag = cipher.getAuthTag();
  
  return {
    encrypted,
    iv: iv.toString('hex'),
    authTag: authTag.toString('hex')
  };
}

// ChaCha20-Poly1305 decryption
function decryptChaCha20(encryptedData, key) {
  const decipher = crypto.createDecipheriv(
    'chacha20-poly1305',
    key,
    Buffer.from(encryptedData.iv, 'hex'),
    { authTagLength: 16 }
  );
  
  decipher.setAuthTag(Buffer.from(encryptedData.authTag, 'hex'));
  
  let decrypted = decipher.update(encryptedData.encrypted, 'hex', 'utf8');
  decrypted += decipher.final('utf8');
  
  return decrypted;
}

// RSA encryption
function encryptRSA(text, publicKey) {
  const textBuffer = Buffer.from(text, 'utf8');
  const maxChunkSize = 190;
  const chunks = [];
  
  for (let i = 0; i < textBuffer.length; i += maxChunkSize) {
    const chunk = textBuffer.slice(i, i + maxChunkSize);
    const encrypted = crypto.publicEncrypt(
      {
        key: publicKey,
        padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
        oaepHash: 'sha256'
      },
      chunk
    );
    chunks.push(encrypted.toString('hex'));
  }
  
  return {
    encrypted: chunks,
    chunkCount: chunks.length
  };
}

// RSA decryption
function decryptRSA(encryptedData, privateKey) {
  const chunks = encryptedData.encrypted;
  const decryptedChunks = [];
  
  for (const chunk of chunks) {
    const decrypted = crypto.privateDecrypt(
      {
        key: privateKey,
        padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
        oaepHash: 'sha256'
      },
      Buffer.from(chunk, 'hex')
    );
    decryptedChunks.push(decrypted);
  }
  
  const fullBuffer = Buffer.concat(decryptedChunks);
  return fullBuffer.toString('utf8');
}

// Benchmark function
async function benchmark(label, encryptFn, decryptFn, key, text, iterations = 100) {
  console.log(`\n${label}:`);
  console.log('─'.repeat(50));
  
  const times = [];
  
  for (let i = 0; i < iterations; i++) {
    const start = process.hrtime.bigint();
    
    // Encrypt if encryption function provided
    let dataToSend = text;
    if (encryptFn) {
      const encrypted = encryptFn(text, key);
      dataToSend = JSON.stringify(encrypted);
    }
    
    // Send to server
    const storeResponse = await makeRequest('POST', '/store', { text: dataToSend });
    const id = storeResponse.id;
    
    // Retrieve from server
    const getResponse = await makeRequest('GET', `/strings/${id}`);
    
    // Decrypt if decryption function provided
    if (decryptFn) {
      const encryptedData = JSON.parse(getResponse.text);
      const decrypted = decryptFn(encryptedData, key);
      // Verify decryption worked
      if (decrypted !== text) {
        throw new Error('Decryption failed - data mismatch!');
      }
    }
    
    const end = process.hrtime.bigint();
    const duration = Number(end - start) / 1_000_000; // Convert to milliseconds
    times.push(duration);
  }
  
  // Calculate statistics
  const avg = times.reduce((a, b) => a + b, 0) / times.length;
  const min = Math.min(...times);
  const max = Math.max(...times);
  const sorted = times.sort((a, b) => a - b);
  const median = sorted[Math.floor(sorted.length / 2)];
  
  console.log(`Iterations: ${iterations}`);
  console.log(`Average:    ${avg.toFixed(3)} ms`);
  console.log(`Median:     ${median.toFixed(3)} ms`);
  console.log(`Min:        ${min.toFixed(3)} ms`);
  console.log(`Max:        ${max.toFixed(3)} ms`);
  
  return { avg, median, min, max };
}

// Main function
async function run() {
  try {
    // Generate keys (32 bytes for AES-256 and ChaCha20)
    const aesKey = crypto.randomBytes(32);
    const chachaKey = crypto.randomBytes(32);
    
    // Generate RSA key pair (2048-bit)
    const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', {
      modulusLength: 2048,
      publicKeyEncoding: {
        type: 'spki',
        format: 'pem'
      },
      privateKeyEncoding: {
        type: 'pkcs8',
        format: 'pem'
      }
    });
    
    const testString = 'Lorem ipsum dolor sit amet, consectetur adipiscing elit. Fusce faucibus ornare lorem at volutpat. Sed vulputate augue eu neque elementum tincidunt. Aliquam sed massa libero. Curabitur eleifend vehicula mauris, ut viverra justo ultricies non. Integer ornare et enim id suscipit. Vivamus accumsan sollicitudin nisi lacinia eleifend. Nam varius justo erat, quis mollis turpis pulvinar in. Pellentesque imperdiet, nisl et imperdiet eleifend, ante elit viverra sapien, ac laoreet massa justo et nisl. Nullam malesuada gravida dolor, quis imperdiet est fermentum ullamcorper. Integer turpis enim, volutpat ut luctus id, ullamcorper ac felis. Praesent urna dolor, consequat eu bibendum at, eleifend sed elit. Suspendisse nibh sapien, dignissim et ligula sit amet, scelerisque efficitur sapien. Fusce vel imperdiet lacus. Aenean ultricies nunc odio, a tempor arcu pharetra at. Vestibulum ante ipsum primis in faucibus orci luctus et ultrices posuere cubilia curae;Vivamus ornare sagittis mattis. Aenean at nulla purus. In nisi sem, egestas a mauris quis, tempus posuere lectus. Proin a metus condimentum, commodo nisi a, maximus quam. Duis sed venenatis urna, id placerat nibh. Orci varius natoque penatibus et magnis dis parturient montes, nascetur ridiculus mus. Aenean fringilla fermentum pulvinar. Praesent nisl urna, ultricies et ornare quis, varius non purus. Cras fermentum pulvinar eleifend. Vivamus vel est ante. Fusce malesuada iaculis libero vitae vulputate. Integer laoreet ut nisi quis tempor. Aenean nunc massa, porta at venenatis sed, cursus id ante. In vestibulum velit non elit dictum, eget pharetra lectus laoreet. Phasellus sed vulputate massa.Quisque hendrerit congue justo quis porttitor. Sed eget augue aliquam, imperdiet mauris non, ultricies sapien. Donec eget leo vel est aliquam elementum. Integer id suscipit lorem. In libero urna, porta eget massa eu, porta tincidunt felis. Vestibulum ut facilisis urna. Quisque pretium molestie imperdiet. Vivamus auctor, ante at tristique blandit, nulla dui convallis risus, suscipit scelerisque dolor quam vel elit. Integer lobortis tortor nisi, at facilisis risus suscipit at. Donec ut nisl ut ante ultricies tincidunt et sit amet tortor. Aenean quis pulvinar lacus. Mauris ut consequat nulla. Quisque id tortor quis purus fringilla dignissim. Integer eget ex vitae mauris vehicula vestibulum. Nullam et lectus eros.Ut ut erat fermentum, pellentesque nisl a, fringilla nulla. Quisque rutrum, turpis sed ullamcorper ultrices, erat felis convallis libero, at consequat neque metus eu velit. Maecenas interdum, libero pulvinar porta vehicula, dui mauris lobortis risus, laoreet commodo ex ante a leo. Quisque vitae auctor mauris. Praesent non neque fringilla, vehicula odio ac, consequat velit. Nam euismod libero vel odio luctus pretium. Nullam porttitor, arcu a finibus aliquam, est lectus maximus erat, ac pellentesque felis erat eget enim. Phasellus sed dui sit amet magna aliquet pulvinar. Aliquam eu sem eu erat gravida interdum. Cras sem nibh, molestie non pulvinar sed, mollis vitae tortor. Ut eu lorem vitae diam efficitur sagittis. Ut euismod orci leo, vel eleifend urna ornare sit amet. Fusce non pharetra odio. Nam aliquet, lacus eget gravida volutpat, ligula nibh scelerisque dui, ut blandit arcu tellus ac risus.Aliquam at placerat massa. Maecenas libero dui, bibendum sed augue sit amet, iaculis varius dui. Etiam auctor elementum faucibus. Ut dui eros, tempor ut urna ac, hendrerit rhoncus metus. Curabitur nec erat interdum, venenatis lacus pellentesque, pellentesque purus. In blandit vulputate metus, sed accumsan leo auctor vel. Curabitur non tellus condimentum, pharetra orci et, maximus diam. Suspendisse potenti. Morbi a vehicula sem.Quisque ut mattis ante, eget rhoncus felis. Mauris nec nisl at sapien consectetur efficitur. Quisque at tempus erat. Fusce tristique vestibulum libero, rhoncus sodales ex luctus at. Vivamus nec porta eros, vel molestie ante. Cras vehicula eget tortor eget maximus. Phasellus in facilisis metus, vitae lacinia dolor. Praesent arcu lacus, varius vitae eros a, venenatis molestie metus. Nullam vel sapien ac ipsum congue semper id sed massa. Aenean eu tincidunt ligula, nec tempor risus. Morbi vel pellentesque neque. Sed sit amet nisi imperdiet ligula fringilla dapibus. Vestibulum ante ipsum primis in faucibus orci luctus et ultrices posuere cubilia curae; Aenean non volutpat libero. Quisque accumsan sodales libero et tincidunt.Maecenas vel ipsum gravida, dapibus elit hendrerit, facilisis quam. Aliquam dapibus porta felis a suscipit. Quisque volutpat quis justo interdum semper. Nulla et mollis ante. Fusce nec fringilla lacus, a vestibulum leo. Nam id quam eleifend, vehicula orci sed, volutpat dui. Vivamus porta nisi quam, at aliquam est faucibus sit amet. Aliquam augue lacus, consectetur at commodo sed, venenatis eget nisl. Suspendisse porttitor augue quis eleifend egestas. Ut rutrum diam felis, eget lobortis urna bibendum vel. Nam orci ex, commodo nec elementum a, ornare ut lectus. Donec et aliquam elit, quis varius nulla. Duis ut ullamcorper metus. Aenean nec mi quis lacus dictum mattis eget vel enim. Curabitur turpis risus, tempus et maximus a, condimentum nec metus.Etiam massa ligula, blandit et consequat ac, euismod sit amet tellus. Proin ut fringilla libero. Nunc quis justo id ex cursus ultricies. Proin finibus id quam ac sodales. Donec augue enim, finibus non feugiat a, vehicula convallis odio. Duis sollicitudin porta ornare. Pellentesque habitant morbi tristique senectus et netus et malesuada fames ac turpis egestas. Nunc venenatis arcu et lorem tempor pharetra. Nulla interdum quam eget est aliquet sollicitudin. Vestibulum ac tellus quis nisi maximus feugiat. Vestibulum semper mollis dolor. Pellentesque a tellus in nulla egestas iaculis. Phasellus at mauris quis neque porttitor interdum.In tincidunt mi sagittis blandit luctus. Nam tempus, nunc at commodo faucibus, risus tortor vehicula quam, vitae blandit erat mi at est. Integer in lacinia justo, id sodales nisi. Mauris vulputate laoreet consequat. Suspendisse ullamcorper a augue ac ornare. Donec eu tincidunt nibh. Class aptent taciti sociosqu ad litora torquent per conubia nostra, per inceptos himenaeos. Donec eu nunc vel nibh blandit tristique. Suspendisse a mollis massa. Nunc vel scelerisque nulla, ac bibendum orci. Aenean molestie, velit at congue mattis, neque nibh sodales est, eu vestibulum neque nunc eget sem. Aliquam auctor ligula lorem, non malesuada dolor laoreet et. Donec id ex vitae dolor bibendum placerat. Phasellus non quam aliquet, consequat metus vitae, blandit nunc. Integer vitae metus dapibus, viverra elit vitae, volutpat purus. Maecenas consectetur dui eget nibh ultricies cursus.Sed vel dui sit amet tortor lacinia dapibus. Sed ut blandit quam. Praesent molestie sagittis lacinia. Phasellus eget dolor eget ipsum elementum suscipit. Nunc bibendum ante ac odio lobortis, non scelerisque diam pretium. Vivamus id risus leo. Sed non nisl euismod, tempus dolor quis, aliquet orci. Fusce ut purus consequat, malesuada risus vitae, ullamcorper magna.Sed a aliquet urna. Phasellus varius, purus vitae ultrices ullamcorper, mi odio tristique elit, et tempor tortor orci vel purus. Suspendisse tristique, erat ac eleifend ultrices, orci tellus imperdiet felis, et iaculis magna odio faucibus nunc. Quisque posuere rhoncus mauris. In hac habitasse platea dictumst. Interdum et malesuada fames ac ante ipsum primis in faucibus. Quisque vestibulum finibus velit ornare tristique. Phasellus vel placerat diam. Vestibulum tempor justo nec est ornare faucibus nec id magna. Nunc eleifend, nisl ac finibus volutpat, nisi metus pulvinar neque, quis feugiat urna odio ut diam. Sed sed sem ullamcorper, porttitor risus eu, scelerisque nisi. Integer semper enim ut cursus ornare. Suspendisse hendrerit turpis at augue mollis, nec sodales augue auctor. Sed porttitor nisl eu mauris fermentum convallis. Donec felis dui, condimentum eget faucibus ac, volutpat vel metus. Praesent mattis dolor lectus, nec aliquet ex finibus vel.Etiam nec porta felis. In nec felis bibendum, accumsan mauris in, iaculis nulla. Suspendisse sagittis condimentum erat eu ornare. Nullam ullamcorper leo velit, ac faucibus arcu mollis eget. Maecenas porta euismod ante et condimentum. Curabitur mollis felis non massa dignissim, fringilla commodo sem vestibulum. Quisque ornare ut tortor laoreet rutrum.Nam vitae ipsum eget libero mollis sagittis. Mauris tempus placerat nunc, a scelerisque sapien ullamcorper vestibulum. Etiam vehicula orci massa, sit amet congue tellus euismod iaculis. Integer viverra nibh vel bibendum aliquam. Nullam fringilla felis neque, a consectetur turpis commodo vitae. Suspendisse potenti. Curabitur sit amet risus ut turpis interdum pretium. Morbi efficitur, dolor at mollis lacinia, sapien massa pharetra purus, dictum vestibulum quam velit non lectus. Aliquam efficitur mi a feugiat egestas. Nulla facilisi. Maecenas commodo enim quis velit placerat pulvinar. Maecenas ac tortor at mauris tincidunt gravida. Nunc gravida velit vel eros malesuada fringilla. Pellentesque tincidunt semper porttitor. Praesent blandit ipsum nunc, quis aliquam dolor feugiat vitae.Curabitur vel massa a sem tempus molestie. Maecenas ut ligula metus. Quisque sodales aliquam elit non efficitur. Donec et nibh ultricies, placerat lorem quis, elementum ante. Sed laoreet viverra erat, sed vulputate libero fermentum ut. Ut eget aliquet lorem. Vestibulum pharetra dolor lacinia, semper enim vel, malesuada eros.Vestibulum accumsan risus lectus, non varius tellus efficitur in. Etiam volutpat consectetur diam, dictum blandit purus blandit at. Sed luctus, ex id pellentesque laoreet, ante lacus molestie diam, id mattis enim risus eget lacus. Sed suscipit interdum sapien sit amet sollicitudin. Praesent elementum urna odio, vel pharetra tortor suscipit a. Etiam pulvinar nec risus nec placerat. Nam vitae nulla in risus pretium rhoncus a vel justo. Integer feugiat porttitor lacinia. Suspendisse laoreet sit amet quam nec rutrum. Proin sodales varius aliquam. Suspendisse nec tristique neque.Aliquam elementum non orci venenatis laoreet. Quisque efficitur ac est ut commodo. Aliquam sed turpis aliquam nisi mollis dapibus laoreet nec odio nec. ';
    
    console.log('Starting encryption performance comparison...');
    console.log('Test string length:', testString.length, 'characters');
    console.log('Number of iterations per test: 100');
    
    // Run benchmarks
    const unencrypted = await benchmark(
      '1. Unencrypted (store + retrieve)',
      null,
      null,
      null,
      testString
    );
    
    const aes = await benchmark(
      '2. AES-256-GCM (encrypt + store + retrieve + decrypt)',
      encryptAES,
      decryptAES,
      aesKey,
      testString
    );
    
    const chacha = await benchmark(
      '3. ChaCha20-Poly1305 (encrypt + store + retrieve + decrypt)',
      encryptChaCha20,
      decryptChaCha20,
      chachaKey,
      testString
    );
    
    const rsaEncrypt = (text, key) => encryptRSA(text, publicKey);
    const rsaDecrypt = (encryptedData, key) => decryptRSA(encryptedData, privateKey);
    
    const rsa = await benchmark(
      '4. RSA-2048-OAEP (encrypt + store + retrieve + decrypt)',
      rsaEncrypt,
      rsaDecrypt,
      null,
      testString
    );
    
    // Summary
    console.log('\n' + '='.repeat(50));
    console.log('SUMMARY (Average Times):');
    console.log('='.repeat(50));
    console.log(`Unencrypted:       ${unencrypted.median.toFixed(3)} ms (baseline)`);
    console.log(`AES-256-GCM:       ${aes.median.toFixed(3)} ms (+${(aes.median - unencrypted.median).toFixed(3)} ms)`);
    console.log(`ChaCha20-Poly1305: ${chacha.median.toFixed(3)} ms (+${(chacha.median - unencrypted.median).toFixed(3)} ms)`);
    console.log(`RSA-2048-OAEP:     ${rsa.median.toFixed(3)} ms (+${(rsa.median - unencrypted.median).toFixed(3)} ms)`);
    
    console.log('\nEncryption Overhead:');
    console.log(`AES-256-GCM:       ${((aes.median / unencrypted.median - 1) * 100).toFixed(2)}% slower`);
    console.log(`ChaCha20-Poly1305: ${((chacha.median / unencrypted.median - 1) * 100).toFixed(2)}% slower`);
    console.log(`RSA-2048-OAEP:     ${((rsa.median / unencrypted.median - 1) * 100).toFixed(2)}% slower`);
    
    const faster = aes.median < chacha.median ? 'AES-256-GCM' : 'ChaCha20-Poly1305';
    const diff = Math.abs(aes.median - chacha.median);
    console.log(`\n${faster} is faster by ${diff.toFixed(3)} ms on average`);
    
  } catch (error) {
    console.error('Error:', error.message);
    console.error('Make sure the server is running on localhost:3000');
  }
}

run();
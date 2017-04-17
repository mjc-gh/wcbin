const BIN_TYPES = ['application/octet-stream', 'application/macbinary'];
const IMG_TYPES = ['image/jpeg', 'image/jpg', 'image/png', 'image/svg'];
const TYPES = [].concat(IMG_TYPES);

function halt(ev){
    ev.stopPropagation();
    ev.preventDefault();

    return false;
}

function reset(){
    Array.from(document.querySelectorAll('#alert, #results')).forEach(element => {
        element.innerHTML = '';
    });
}

function renderError(err){
    document.getElementById('alert').innerText = err == null ?
        '' : err.message || err.name || err;
}

function getPassphrase(){
    const passphrase = document.querySelector('#form input[name="passphrase"]').value;

    const buf = new ArrayBuffer(passphrase.length * 2);
    const bufView = new Uint16Array(buf);

    for (let i = 0, len = passphrase.length; i < len; i++) {
        bufView[i] = passphrase.charCodeAt(i);
    }

    return buf;
}

function deriveKey(passphrase, salt){
    return new Promise(resolve => {
        const baseAlgo = { name: 'PBKDF2' };

        function deriveKeyFromPhrase(){
            return window.crypto.subtle.importKey(
                'raw', passphrase, baseAlgo, false, ['deriveKey']
            );
        }

        function deriveAesKey(key){
            const algorithm = Object.assign({}, baseAlgo, {
                salt: salt, iterations: 10000, hash: { name: 'SHA-256' }
            });

            const dkType = { name: 'AES-GCM', length: 256 };
            const useage = ['encrypt', 'decrypt'];

            return window.crypto.subtle.deriveKey(
                algorithm, key, dkType, false, useage
            );
        }

        return deriveKeyFromPhrase().then(deriveAesKey).then(resolve);
    });
}

function encrypt(){
    const input = document.querySelector('#form input[name="file"]');
    const files = Array.from(input.files);

    function validate(){
        return new Promise((resolve, reject) => {
            if (!document.getElementById('form').checkValidity())
                reject();

            if (files.length < 1)
                reject('Please provide at least one image or text file!')

            files.forEach(file => {
                if (!TYPES.includes(file.type))
                    reject('Invalid file type found; images only please (for now...)');
            });

            resolve();
        });
    }

    function convertFiles(){
        return Promise.all(files.map(file => {
            return new Promise((resolve, reject) => {
                const reader = new FileReader;

                reader.onload = () => resolve({ buffer: reader.result, type: file.type });
                reader.onerror = reject;
                reader.readAsArrayBuffer(file);
            });
        }));
    }

    function createPayload(results){
        // The payload is a Uint32Array with the following format
        // [ length of metadata as a u32 (4 bytes) | metadata | filedata ]
        const metadata = results.map(result => {
            return { type: result.type, size: result.buffer.byteLength };
        });

        const metadataJson = JSON.stringify(metadata);

        const metadataSz = metadataJson.length * 2;
        const filedataSz = metadata.reduce((sum, md) => sum + md.size, 0);

        let payloadSz = 8 + metadataSz + filedataSz;

        if (payloadSz % 2 !== 0)
            payloadSz += 1;

        const payload = new ArrayBuffer(payloadSz);

        const szView = new Uint32Array(payload, 0, 1);
        const mdView = new Uint16Array(payload, 4, metadataJson.lengh);
        const fdView = new Uint8Array(payload, 4 + metadataSz);

        // Write metadata JSON length as u32 (4 bytes)
        szView[0] = metadataSz;

        // Write metadata JSON string (2 bytes per charCodeAt)
        for (let i = 0, len = metadataJson.length; i < len; i++) {
            mdView[i] = metadataJson.charCodeAt(i);
        }

        // Write filedata byte for byte
        let fdIndex = 0;

        results.forEach(result => {
            const buf  = result.buffer;
            const view = new Uint8Array(buf);

            for (let i = 0, len = buf.byteLength; i < len; i++)
                fdView[fdIndex++] = view[i];
        });

        return payload;
    }

    function encryptPayload(payload, passphrase){
        const salt = window.crypto.getRandomValues(new Uint8Array(16));

        return deriveKey(passphrase, salt).then(key => {
            const iv = window.crypto.getRandomValues(new Uint8Array(12));
            const algorithm = { name: 'AES-GCM', iv: iv, tagLength: 128 };

            function writeOutput(encrypted){
                const length = salt.byteLength + iv.byteLength + encrypted.byteLength;

                const output = new ArrayBuffer(length);
                const outView = new Uint8Array(output);

                let outIndex = 0;

                function write(bufView){
                    for (let i = 0, len = bufView.byteLength; i < len; i++){
                        outView[outIndex++] = bufView[i];
                    }
                }

                write(salt);
                write(iv);
                write(new Uint8Array(encrypted));

                return output;
            }

            return window.crypto.subtle.encrypt(
                algorithm, key, payload
            ).then(writeOutput);
        });
    }

    function saveAsFile(fileName, encrypted){
        const blob = new Blob([encrypted], { type: 'application/octet-stream' });
        const url = window.URL.createObjectURL(blob);

        const anchor = document.getElementById('download');

        anchor.href = url;
        anchor.download = fileName;
        anchor.click();

        window.URL.revokeObjectURL(url);
    }

    validate().then(() => {
        convertFiles().then(results => {
            const payload = createPayload(results);

            return encryptPayload(payload, getPassphrase()).then(encrypted => {
                saveAsFile('cryptablob.bin', encrypted);
            });
        });
    }).catch(renderError);
}

function decrypt(){
    const results = document.getElementById('results');

    function convertFile(){
        return new Promise((resolve, reject) => {
            const input = document.querySelector('#form input[name="file"]');
            const file = input.files[0];

            if (!file)
                reject('Please provide an encrypted bin file');
            else if (!BIN_TYPES.includes(file.type))
                reject('Encrypt bin file is the wrong file type');

            const reader = new FileReader;

            reader.onload = () => resolve(reader.result);
            reader.onerror = reject;
            reader.readAsArrayBuffer(file);
        });
    }

    function decryptPayload(payload, passphrase){
        const view = new Uint8Array(payload);
        const salt = view.slice(0, 16);
        const iv = view.slice(16, 16 + 12);

        const ciphertext = new Uint8Array(payload, 16 + 12);

        return deriveKey(passphrase, salt).then(key => {
            const algorithm = { name: 'AES-GCM', iv: iv, tagLength: 128 };

            return window.crypto.subtle.decrypt(
                algorithm, key, ciphertext
            ).catch(() => Promise.reject('Decryption failed. Invalid key!'));
        });
    }

    function process(payload){
        const szView = new Uint32Array(payload, 0, 1);
        const metadataSz = szView[0];

        const mdView = new Uint16Array(payload, 4, (metadataSz / 2));
        const fdView = new Uint8Array(payload, 4 + metadataSz);

        const metadata = JSON.parse(String.fromCharCode.apply(null, mdView));

        let fdIndex = 0;

        metadata.forEach(file => {
            const fileBuf = new ArrayBuffer(file.size);
            const fileView = new Uint8Array(fileBuf);

            for (let i = 0, len = file.size; i < len; i++){
                fileView[i] = fdView[fdIndex++];
            }

            render(file.type, fileBuf);
        });
    }

    function render(type, buffer){
        if (IMG_TYPES.includes(type))
            renderImage(type, buffer);
    }

    function renderImage(type, buffer){
        const blob = new Blob([buffer], { type: type });
        const image = new Image;
        const reader = new FileReader;

        append(image);

        reader.onload = () => { image.src = reader.result; };
        reader.readAsDataURL(blob);
    }

    function append(element){
        results.appendChild(element);
    }

    convertFile().then(buffer => {
        return decryptPayload(buffer, getPassphrase()).then(process);
    }).catch(renderError);
}

function checkBrowserSupport(){
    const ua = (navigator && navigator.userAgent) || '';

    const hasCrypto = 'crypto' in window;
    const hasSubtleCrypto = 'subtle' in window.crypto;

    if (!('crypto' in window) ||
        !('subtle' in window.crypto) ||
        !('Blob' in window) ||
        !('download' in document.createElement('a'))
    ) document.body.setAttribute('class', 'unsupported');
}


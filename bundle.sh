browserify index.js -o elastos-wallet-js-1.0.9.js
terser --compress --mangle -- elastos-wallet-js-1.0.9.js > elastos-wallet-js-1.0.9.min.js
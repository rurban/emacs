;;; nettle.el --- Interface to libnettle/libhogweed  -*- lexical-binding: t; -*-

;; Copyright (C) 2013  Teodor Zlatanov

;; Author: Teodor Zlatanov <tzz@lifelogs.com>
;; Keywords: data

;; This program is free software; you can redistribute it and/or modify
;; it under the terms of the GNU General Public License as published by
;; the Free Software Foundation, either version 3 of the License, or
;; (at your option) any later version.

;; This program is distributed in the hope that it will be useful,
;; but WITHOUT ANY WARRANTY; without even the implied warranty of
;; MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
;; GNU General Public License for more details.

;; You should have received a copy of the GNU General Public License
;; along with this program.  If not, see <http://www.gnu.org/licenses/>.

;;; Commentary:

;; Provides basic functions to interface with libnettle and libhogweed
;; through nettle.c

;; Test with ./emacs --batch --load "/path/to/nettle.el" -f ert-run-tests-batch

;;; Code:

(require 'cl)
(require 'ert)
(require 'hex-util)

;;;###autoload
(defcustom nettle-payloads-store-secrets nil
  "Whether the Nettle interface should store secrets in the payloads.
The secrets are: the key, the IV, and the original input.
Set this to t if you're debugging."
  :version "24.4"
  :type 'boolean)

(cl-defstruct nettle-payload length data key iv input cipher cipher-mode)

(defun nettle-payload-hexdump (payload)
  (encode-hex-string (nettle-payload-data payload)))

(defun nettle-payload-fulldump (payload)
  (let ((key (funcall (nettle-payload-key payload)))
        (iv (funcall (nettle-payload-iv payload)))
        (input (funcall (nettle-payload-input payload))))
    (format "%s with cipher %s, key(%d) %S, IV(%d) %S, input(%d) %S => (%d) %s"
            (nettle-payload-cipher-mode payload)
            (nettle-payload-cipher payload)
            (length key) (when key (encode-hex-string key))
            (length iv) (when iv (encode-hex-string iv))
            (length input) (when input (encode-hex-string input))
            (nettle-payload-length payload)
            (nettle-payload-hexdump payload))))

(defsubst nettle-make-secret (secret)
  (if nettle-payloads-store-secrets
      (lexical-let ((p (copy-sequence secret)))
        (lambda () p))
    (lambda () nil)))

(defun nettle-encrypt (input key iv cipher cipher-mode)
  (make-nettle-payload :length (length input)
                       :cipher cipher
                       :cipher-mode cipher-mode
                       :input (nettle-make-secret input)
                       :key (nettle-make-secret key)
                       :iv (nettle-make-secret iv)
                       :data (nettle-crypt t input key iv cipher cipher-mode)))

(defun nettle-decrypt (payload key iv cipher cipher-mode)
  (let ((data (nettle-crypt
               nil
               (nettle-payload-data payload)
               key iv cipher cipher-mode)))
    (substring data 0 (nettle-payload-length payload))))

(ert-deftest test-nettle-001-hashes ()
    "Test the Nettle hashing functions"
    (progn
      ;; we expect at least 7 hash methods
      (should (> (length (nettle-hashes)) 7))
      (let* ((inputs '(""
                       "some data"
                       "lots and lots of data lots and lots of data lots and lots of data lots and lots of data lots and lots of data lots and lots of data lots and lots of data lots and lots of data lots and lots of data lots and lots of data lots and lots of data lots and lots of data lots and lots of data lots and lots of data lots and lots of data lots and lots of data lots and lots of data lots and lots of data lots and lots of data lots and lots of data lots and lots of data "
                       "data and more data to go over the block limit!"
                       "data and more data to go over the block limit"))
             (algomap '(md5 sha1 sha224 sha256 sha384 sha512))
             ;; only test the algorithms supported by `secure-hash'
             (hashes (delete nil (mapcar
                                  (lambda (x)
                                    (let ((sym (intern (car x))))
                                      (car (member sym algomap))))
                                  (nettle-hashes)))))
      (dolist (hash hashes)
        (dolist (input inputs)
          ;; we use encode-hex-string to ensure the tests are readable
          (should (string-equal (encode-hex-string (nettle-hash
                                                    input
                                                    (symbol-name hash)))
                                (encode-hex-string (secure-hash
                                                    hash
                                                    input
                                                    nil nil t)))))))))

(ert-deftest test-nettle-002-ciphers ()
    "Test the Nettle ciphers"
    ;; we expect at least 10 ciphers
    (should (> (length (nettle-ciphers)) 10))
    (let ((keys '("mykey" "mykey2"))
          (inputs '(""
                    "some data"
                    "lots and lots of data lots and lots of data lots and lots of data lots and lots of data lots and lots of data lots and lots of data lots and lots of data lots and lots of data lots and lots of data lots and lots of data lots and lots of data lots and lots of data lots and lots of data lots and lots of data lots and lots of data lots and lots of data lots and lots of data lots and lots of data lots and lots of data lots and lots of data lots and lots of data "
                    "data and more data to go over the block limit!"
                    "data and more data to go over the block limit"))
          (ivs '("" "init" "init2"))
          ; arcfour128 generates a FPE, disabled for now
          (ciphers (delete "arcfour128" (mapcar 'car (nettle-ciphers))))
          (cipher-modes (nettle-cipher-modes))
          tests test test2 result dump payload)

      (dolist (mode cipher-modes)
        (dolist (cipher ciphers)
          (dolist (iv ivs)
            (dolist (input inputs)
              (dolist (key keys)
                (setq tests (cons (list input key iv cipher mode)
                                 tests)))))))

      (while (setq test (pop tests))
        ;; test2 = the original test but replacing the input with the payload
        (setq test2 (copy-sequence test))
        (setq payload (apply 'nettle-encrypt test))
        (setf (nth 0 test2) payload)

        (setq result (apply 'nettle-decrypt test2))

        (should (string-equal (car test) result)))))

;;; Testing from the command line:
;;; echo e36a9d13c15a6df23a59a6337d6132b8f7cd5283cb4784b81141b52343a18e5f5e5ee8f5553c23167409dd222478bc30 | perl -lne 'print pack "H*", $_' | openssl enc -aes-128-ctr -d  -nosalt -K 6d796b657932 -iv 696e697432 | od -x
;;; Testing the equivalent CTR encryption:
;;; (message "\t 111 \t %s" (nettle-payload-fulldump (nettle-encrypt "data and more data to go over the block limit" "mykey2" "init2" "aes128" "CTR")))
;;; (message "\t 222 \t %s" (nettle-payload-fulldump (nettle-encrypt (decode-hex-string "e36a9d13c15a6df23a59a6337d6132b8f7cd5283cb4784b81141b52343a18e5f5e5ee8f5553c23167409dd222478bc30") "mykey2" "init2" "aes128" "CTR")))
;;; (message "\t 333 \t %s" (encode-hex-string (nettle-crypt t   (decode-hex-string "e36a9d13c15a6df23a59a6337d6132b8f7cd5283cb4784b81141b52343a18e5f5e5ee8f5553c23167409dd222478bc30") "mykey2" "init2" "aes128" "CTR")))
;;; (message "\t 444 \t %s" (encode-hex-string (nettle-crypt nil (decode-hex-string "e36a9d13c15a6df23a59a6337d6132b8f7cd5283cb4784b81141b52343a18e5f5e5ee8f5553c23167409dd222478bc30") "mykey2" "init2" "aes128" "CTR")))

(ert-deftest test-nettle-003-more-ciphers ()
    "Test the Nettle ciphers from a test set"
    (let ((tests '(
                   ("5d563f6d1cccf236051c0c5c1c58f28f" "f69f2445df4f9b17ad2b417be66c3710" "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4" "e31a6055297d96ca3330cdf1b1860a83" "camellia256" "CBC")
                   ("e31a6055297d96ca3330cdf1b1860a83" "30c81c46a35ce411e5fbc1191a0a52ef" "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4" "36cbeb73bd504b4070b1b7de2b21eb50" "camellia256" "CBC")
                   ("36cbeb73bd504b4070b1b7de2b21eb50" "ae2d8a571e03ac9c9eb76fac45af8e51" "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4" "e6cfa35fc02b134a4d2c0b6737ac3eda" "camellia256" "CBC")
                   ("e6cfa35fc02b134a4d2c0b6737ac3eda" "6bc1bee22e409f96e93d7e117393172a" "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4" "000102030405060708090a0b0c0d0e0f" "camellia256" "CBC")
                   ("01faaa930b4ab9916e9668e1428c6b08" "f69f2445df4f9b17ad2b417be66c3710" "8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b" "37d359c3349836d884e310addf68c449" "camellia192" "CBC")
                   ("37d359c3349836d884e310addf68c449" "30c81c46a35ce411e5fbc1191a0a52ef" "8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b" "5d5a869bd14ce54264f892a6dd2ec3d5" "camellia192" "CBC")
                   ("5d5a869bd14ce54264f892a6dd2ec3d5" "ae2d8a571e03ac9c9eb76fac45af8e51" "8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b" "2a4830ab5ac4a1a2405955fd2195cf93" "camellia192" "CBC")
                   ("2a4830ab5ac4a1a2405955fd2195cf93" "6bc1bee22e409f96e93d7e117393172a" "8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b" "000102030405060708090a0b0c0d0e0f" "camellia192" "CBC")
                   ("74c64268cdb8b8faf5b34e8af3732980" "f69f2445df4f9b17ad2b417be66c3710" "2b7e151628aed2a6abf7158809cf4f3c" "36a84cdafd5f9a85ada0f0a993d6d577" "camellia128" "CBC")
                   ("0f06165008cf8b8b5a63586362543e54" "30c81c46a35ce411e5fbc1191a0a52ef" "2b7e151628aed2a6abf7158809cf4f3c" "a2f2cf671629ef7840c5a5dfb5074887" "camellia128" "CBC")
                   ("a2f2cf671629ef7840c5a5dfb5074887" "ae2d8a571e03ac9c9eb76fac45af8e51" "2b7e151628aed2a6abf7158809cf4f3c" "1607cf494b36bbf00daeb0b503c831ab" "camellia128" "CBC")
                   ("1607cf494b36bbf00daeb0b503c831ab" "6bc1bee22e409f96e93d7e117393172a" "2b7e151628aed2a6abf7158809cf4f3c" "000102030405060708090a0b0c0d0e0f" "camellia128" "CBC")
                   ("7960109fb6dc42947fcfe59ea3c5eb6b" "f69f2445df4f9b17ad2b417be66c3710" "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4" "" "camellia256" "ECB")
                   ("a623d711dc5f25a51bb8a80d56397d28" "30c81c46a35ce411e5fbc1191a0a52ef" "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4" "" "camellia256" "ECB")
                   ("c91d3a8f1aea08a9386cf4b66c0169ea" "ae2d8a571e03ac9c9eb76fac45af8e51" "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4" "" "camellia256" "ECB")
                   ("befd219b112fa00098919cd101c9ccfa" "6bc1bee22e409f96e93d7e117393172a" "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4" "" "camellia256" "ECB")
                   ("909dbd95799096748cb27357e73e1d26" "f69f2445df4f9b17ad2b417be66c3710" "8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b" "" "camellia192" "ECB")
                   ("b40ed2b60eb54d09d030cf511feef366" "30c81c46a35ce411e5fbc1191a0a52ef" "8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b" "" "camellia192" "ECB")
                   ("5713c62c14b2ec0f8393b6afd6f5785a" "ae2d8a571e03ac9c9eb76fac45af8e51" "8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b" "" "camellia192" "ECB")
                   ("cccc6c4e138b45848514d48d0d3439d3" "6bc1bee22e409f96e93d7e117393172a" "8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b" "" "camellia192" "ECB")
                   ("e61925e0d5dfaa9bb29f815b3076e51a" "f69f2445df4f9b17ad2b417be66c3710" "2b7e151628aed2a6abf7158809cf4f3c" "" "camellia128" "ECB")
                   ("a0a1abcd1893ab6fe0fe5b65df5f8636" "30c81c46a35ce411e5fbc1191a0a52ef" "2b7e151628aed2a6abf7158809cf4f3c" "" "camellia128" "ECB")
                   ("0be1f14023782a22e8384c5abb7fab2b" "ae2d8a571e03ac9c9eb76fac45af8e51" "2b7e151628aed2a6abf7158809cf4f3c" "" "camellia128" "ECB")
                   ("432fc5dcd628115b7c388d770b270c96" "6bc1bee22e409f96e93d7e117393172a" "2b7e151628aed2a6abf7158809cf4f3c" "" "camellia128" "ECB")
                   ("2edf1f3418d53b88841fc8985fb1ecf2" "00112233445566778899aabbccddeeff" "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f" "" "camellia256" "ECB")
                   ("b22f3c36b72d31329eee8addc2906c68" "00112233445566778899aabbccddeeff" "000102030405060708090a0b0c0d0e0f1011121314151617" "" "camellia192" "ECB")
                   ("77cf412067af8270613529149919546f" "00112233445566778899aabbccddeeff" "000102030405060708090a0b0c0d0e0f" "" "camellia128" "ECB")
                   ("9acc237dff16d76c20ef7c919e3a7509" "0123456789abcdeffedcba9876543210" "0123456789abcdeffedcba987654321000112233445566778899aabbccddeeff" "" "camellia256" "ECB")
                   ("b4993401b3e996f84ee5cee7d79b09b9" "0123456789abcdeffedcba9876543210" "0123456789abcdeffedcba98765432100011223344556677" "" "camellia192" "ECB")
                   ("67673138549669730857065648eabe43" "0123456789abcdeffedcba9876543210" "0123456789abcdeffedcba9876543210" "" "camellia128" "ECB")
                   ("eb6c52821d0bbbf7ce7594462aca4faab407df866569fd07f48cc0b583d6071f1ec0e6b8" "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20212223" "ff7a617ce69148e4f1726e2f43581de2aa62d9f805532edff1eed687fb54153d" "001cc5b751a51d70a1c1114800000001" "aes256" "CTR")
                   ("f05e231b3894612c49ee000b804eb2a9b8306b508f839d6a5530831d9344af1c" "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f" "f6d66d6bd52d59bb0796365879eff886c66dd51a5b6a99744b50590c87a23884" "00faac24c1585ef15a43d87500000001" "aes256" "CTR")
                   ("145ad01dbf824ec7560863dc71e3e0c0" "53696e676c6520626c6f636b206d7367" "776beff2851db06f4c8a0542c8696f6c6a81af1eec96b4d37fc1d689e6c1c104" "00000060db5672c97aa8f0b200000001" "aes256" "CTR")
                   ("96893fc55e5c722f540b7dd1ddf7e758d288bc95c69165884536c811662f2188abee0935" "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20212223" "02bf391ee8ecb159b959617b0965279bf59b60a786d3e0fe" "0007bdfd5cbd60278dcc091200000001" "aes192" "CTR")
                   ("453243fc609b23327edfaafa7131cd9f8490701c5ad4a79cfc1fe0ff42f4fb00" "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f" "7c5cb2401b3dc33c19e7340819e0f69c678c3db8e6f6a91a" "0096b03b020c6eadc2cb500d00000001" "aes192" "CTR")
                   ("4b55384fe259c9c84e7935a003cbe928" "53696e676c6520626c6f636b206d7367" "16af5b145fc9f579c175f93e3bfb0eed863d06ccfdb78515" "0000004836733c147d6d93cb00000001" "aes192" "CTR")
                   ("c1cf48a89f2ffdd9cf4652e9efdb72d74540a42bde6d7836d59a5ceaaef3105325b2072f" "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20212223" "7691be035e5020a8ac6e618529f9a0dc" "00e0017b27777f3f4a1786f000000001" "aes128" "CTR")
                   ("5104a106168a72d9790d41ee8edad388eb2e1efc46da57c8fce630df9141be28" "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f" "7e24067817fae0d743d6ce1f32539163" "006cb6dbc0543b59da48d90b00000001" "aes128" "CTR")
                   ("e4095d4fb7a7b3792d6175a3261311b8" "53696e676c6520626c6f636b206d7367" "ae6852f8121067cc4bf7a5765577f39e" "00000030000000000000000000000001" "aes128" "CTR")
                   ("b2eb05e2c39be9fcda6c19078c6a9d1b" "f69f2445df4f9b17ad2b417be66c3710" "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4" "39f23369a9d9bacfa530e26304231461" "aes256" "CBC")
                   ("39f23369a9d9bacfa530e26304231461" "30c81c46a35ce411e5fbc1191a0a52ef" "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4" "9cfc4e967edb808d679f777bc6702c7d" "aes256" "CBC")
                   ("9cfc4e967edb808d679f777bc6702c7d" "ae2d8a571e03ac9c9eb76fac45af8e51" "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4" "f58c4c04d6e5f1ba779eabfb5f7bfbd6" "aes256" "CBC")
                   ("f58c4c04d6e5f1ba779eabfb5f7bfbd6" "6bc1bee22e409f96e93d7e117393172a" "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4" "000102030405060708090a0b0c0d0e0f" "aes256" "CBC")
                   ("08b0e27988598881d920a9e64f5615cd" "f69f2445df4f9b17ad2b417be66c3710" "8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b" "571b242012fb7ae07fa9baac3df102e0" "aes192" "CBC")
                   ("571b242012fb7ae07fa9baac3df102e0" "30c81c46a35ce411e5fbc1191a0a52ef" "8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b" "b4d9ada9ad7dedf4e5e738763f69145a" "aes192" "CBC")
                   ("b4d9ada9ad7dedf4e5e738763f69145a" "ae2d8a571e03ac9c9eb76fac45af8e51" "8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b" "4f021db243bc633d7178183a9fa071e8" "aes192" "CBC")
                   ("4f021db243bc633d7178183a9fa071e8" "6bc1bee22e409f96e93d7e117393172a" "8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b" "000102030405060708090a0b0c0d0e0f" "aes192" "CBC")
                   ("3ff1caa1681fac09120eca307586e1a7" "f69f2445df4f9b17ad2b417be66c3710" "2b7e151628aed2a6abf7158809cf4f3c" "73bed6b8e3c1743b7116e69e22229516" "aes128" "CBC")
                   ("73bed6b8e3c1743b7116e69e22229516" "30c81c46a35ce411e5fbc1191a0a52ef" "2b7e151628aed2a6abf7158809cf4f3c" "5086cb9b507219ee95db113a917678b2" "aes128" "CBC")
                   ("5086cb9b507219ee95db113a917678b2" "ae2d8a571e03ac9c9eb76fac45af8e51" "2b7e151628aed2a6abf7158809cf4f3c" "7649abac8119b246cee98e9b12e9197d" "aes128" "CBC")
                   ("7649abac8119b246cee98e9b12e9197d" "6bc1bee22e409f96e93d7e117393172a" "2b7e151628aed2a6abf7158809cf4f3c" "000102030405060708090a0b0c0d0e0f" "aes128" "CBC")
                   ("23304b7a39f9f3ff067d8d8f9e24ecc7" "f69f2445df4f9b17ad2b417be66c3710" "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4" "" "aes256" "ECB")
                   ("b6ed21b99ca6f4f9f153e7b1beafed1d" "30c81c46a35ce411e5fbc1191a0a52ef" "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4" "" "aes256" "ECB")
                   ("591ccb10d410ed26dc5ba74a31362870" "ae2d8a571e03ac9c9eb76fac45af8e51" "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4" "" "aes256" "ECB")
                   ("f3eed1bdb5d2a03c064b5a7e3db181f8" "6bc1bee22e409f96e93d7e117393172a" "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4" "" "aes256" "ECB")
                   ("9a4b41ba738d6c72fb16691603c18e0e" "f69f2445df4f9b17ad2b417be66c3710" "8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b" "" "aes192" "ECB")
                   ("ef7afd2270e2e60adce0ba2face6444e" "30c81c46a35ce411e5fbc1191a0a52ef" "8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b" "" "aes192" "ECB")
                   ("974104846d0ad3ad7734ecb3ecee4eef" "ae2d8a571e03ac9c9eb76fac45af8e51" "8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b" "" "aes192" "ECB")
                   ("bd334f1d6e45f25ff712a214571fa5cc" "6bc1bee22e409f96e93d7e117393172a" "8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b" "" "aes192" "ECB")
                   ("7b0c785e27e8ad3f8223207104725dd4" "f69f2445df4f9b17ad2b417be66c3710" "2b7e151628aed2a6abf7158809cf4f3c" "" "aes128" "ECB")
                   ("43b1cd7f598ece23881b00e3ed030688" "30c81c46a35ce411e5fbc1191a0a52ef" "2b7e151628aed2a6abf7158809cf4f3c" "" "aes128" "ECB")
                   ("f5d3d58503b9699de785895a96fdbaaf" "ae2d8a571e03ac9c9eb76fac45af8e51" "2b7e151628aed2a6abf7158809cf4f3c" "" "aes128" "ECB")
                   ("3ad77bb40d7a3660a89ecaf32466ef97" "6bc1bee22e409f96e93d7e117393172a" "2b7e151628aed2a6abf7158809cf4f3c" "" "aes128" "ECB")
                   ("8ea2b7ca516745bfeafc49904b496089" "00112233445566778899aabbccddeeff" "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f" "" "aes256" "ECB")
                   ("dda97ca4864cdfe06eaf70a0ec0d7191" "00112233445566778899aabbccddeeff" "000102030405060708090a0b0c0d0e0f1011121314151617" "" "aes192" "ECB")
                   ("69c4e0d86a7b0430d8cdb78070b4c55a" "00112233445566778899aabbccddeeff" "000102030405060708090a0b0c0d0e0f" "" "aes128" "ECB")
                   ))
          test expected payload result)
      (while (setq test (pop tests))
        ;; (message "Testing 003-ciphers %S" test)
        (setf (nth 1 test) (decode-hex-string (nth 1 test)))
        (setf (nth 2 test) (decode-hex-string (nth 2 test)))
        (setf (nth 3 test) (decode-hex-string (nth 3 test)))
        (setq expected (pop test))
        (setq payload (apply 'nettle-encrypt test))
        (setq result (substring (nettle-payload-data payload)
                                0
                                (nettle-payload-length payload)))
              (should (string-equal (encode-hex-string result)
                              expected)))))

(ert-deftest test-nettle-004-more-hashes ()
    "Test the Nettle hashes from a test set"
    (let ((tests '(("57edf4a22be3c955ac49da2e2107b67a" "12345678901234567890123456789012345678901234567890123456789012345678901234567890" "md5")
                   ("d174ab98d277d9f5a5611c2c9f419d9f" "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789" "md5")
                   ("c3fcd3d76192e4007dfb496cca67e13b" "abcdefghijklmnopqrstuvwxyz" "md5")
                   ("f96b697d7cb7938d525a2f31aaf161d0" "message digest" "md5")
                   ("900150983cd24fb0d6963f7d28e17f72" "abc" "md5")
                   ("0cc175b9c0f1b6a831c399e269772661" "a" "md5")
                   ("a9993e364706816aba3e25717850c26c9cd0d89d" "abc" "sha1")))
          test expected)
      (while (setq test (pop tests))
        ;; (message "Testing 004-hashes %S" test)
        (setq expected (pop test))
        (should (string-equal (encode-hex-string (apply 'nettle-hash test))
                              expected)))))

(ert-deftest test-nettle-005-hmac-hashes ()
    "Test the Nettle HMAC hashes from a test set"
    (let ((tests '(("f5c5021e60d9686fef3bb0414275fe4163bece61d9a95fec7a273746a437b986" "hello\n" "test" "sha256")
                   ("46b75292b81002fd873e89c532a1b8545d6efc9822ee938feba6de2723161a67" "more and more data goes into a file to exceed the buffer size" "test" "sha256")
                   ("81568ba71fa2c5f33cc84bf362466988f98eba3735479100b4e8908acad87ac4" "more and more data goes into a file to exceed the buffer size" "very long key goes here to exceed the key size" "sha256")
                   ("4bc830005783a73b8112f4bd5f4aa5f92e05b51e9b55c0cd6f9a7bee48371def" "more and more data goes into a file to exceed the buffer size" "" "sha256")))
          test expected)
      (while (setq test (pop tests))
        ;; (message "Testing 005-hmacs %S" test)
        (setq expected (pop test))
        (should (string-equal (encode-hex-string (apply 'nettle-hmac test))
                              expected)))))

(ert-deftest test-nettle-006-pbkdf2-RFC-6070 ()
    "Test the Nettle PBKDF2 SHA1 hashing with the RFC 6070 test set"
    (should (string-equal (encode-hex-string (nettle-pbkdf2 "pass\000word" "sa\000lt" 4096 16 "sha1"))
                          "56fa6aa75548099dcc37d7f03425e0c3"))
    (let ((tests '("0c60c80f961f0e71f3a9b524af6012062fe037a6:password:salt:1:x:sha1"
                   "ea6c014dc72d6f8ccd1ed92ace1d41f0d8de8957:password:salt:2:x:sha1"
                   "4b007901b765489abead49d926f721d065a429c1:password:salt:4096:x:sha1"
                   ;; "eefe3d61cd4da4e4e9945b3d6ba2158c2634e984:password:salt:16777216:x:sha1" ;; enable for a speed test :)
                   "3d2eec4fe41c849b80c8d83662c0e44a8b291a964cf2f07038:passwordPASSWORDpassword:saltSALTsaltSALTsaltSALTsaltSALTsalt:4096:x:sha1"))
          test expected)
      (while (and tests (setq test (split-string (pop tests) ":")))
        (setq expected (pop test))
        (setf (nth 2 test) (string-to-number (nth 2 test)))
        (setf (nth 3 test) (length (decode-hex-string expected)))
        ;; (message "Testing 006-pbkdf2-RFC-6070 %S" test)
        (should (string-equal (encode-hex-string (apply 'nettle-pbkdf2 test))
                              expected)))))

(ert-deftest test-nettle-007-rsa-verify ()
    "Test the Nettle RSA signature verification"
    ;; signature too short
    (should-error (nettle-rsa-verify "Test the Nettle RSA signature"
                                     ""
                                     "Test the Nettle RSA signature"
                                     "sha1"))

    ;; key too short
    (should-error (nettle-rsa-verify "Test the Nettle RSA signature"
                                     "Test the Nettle RSA signature"
                                     ""
                                     "sha1"))

    ;; invalid hashing method
    (should-error (nettle-rsa-verify "Test the Nettle RSA signature"
                                     "Test the Nettle RSA signature"
                                     ""
                                     "no such method"))

    ;; key generated with:
    ;; openssl genrsa -out privkey.pem 2048
    ;; openssl rsa -in privkey.pem -pubout > pubkey.pem
    (let* ((key (substring "
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAreGA/Qky9W3izQV0kzba
7wKl/wzwxkbbQxvcUqUT1krgAbO/n1tYFjXdJZoWwbMO/qv7NRoMDY4yPWGpsQfY
+PSIknAhTZVbgwXrm/wb37+hKRKax2UZ9A/Rx4vJZRYlkpvZ9LbBziseFNN7SMWW
qkjBO/NeT8/I9mURDa+4RoYfT6ZwjTvt808PH7uIghk+MHAx9EMBAfafF1Jn9TqW
y+Hgdqik9sZteMvCumvGK4grSwzdfPO5I05tt/0I7QVPxlXbHIk/bBsE7mpgOxur
P0DAkFKtYDM7oZPBwB6X778ba2EEFKPpVIyzw/jlDPd9PB6gE6dixmax3Hlg69RI
EwIDAQAB
-----END PUBLIC KEY-----
" 28 426))
           ;; 24 skipped bytes are the header
           (key-bitstring (substring (base64-decode-string key) 24)))
    ;; invalid signature, valid key
    (should-not (nettle-rsa-verify "Test the Nettle RSA signature"
                                   "Test the Nettle RSA signature"
                                   key-bitstring
                                   "sha1"))
    ;; valid signature, valid key
    ; doesn't work; generated with "openssl rsautl -sign -in /tmp/test -inkey /tmp/privkey.pem" but contains other baggage
    (should (nettle-rsa-verify "Test the Nettle RSA signature"
                               (decode-hex-string "abf710d920de0a210167e62995d5cb06fb0ff6a3f81e2f1965dd3f4716883ab61b7dec40d1ebde89b0657473a434d0333177f183f71a9f4b84a49781b1e4bc440e042f2eb4441000ba07168cdb190c5aebba8c433420f6fc28b6997cbfee061170210bfa65294199e6d6c8c5e1a16421942371f6115d77263b859a75645b6b70d56f14ad378c8499318ff05eda9d24a61d854a3d7f6b67b037abb8d25e4b11ca3e42bdb823cfac34c70057ecd55cbb8449346c0824b46f6c668d14f1744bad7d05470953981df32fde24d2a1f27e58bf9e7d99b20b39b25844c53945dcbbd8b406e78bc0b8aee48c0ec8a26e70301eeeb12ba733e0baf7b82c8e25ac3ee89291")
                               key-bitstring
                               "sha1"))
))

;; (message (encode-hex-string (nettle-pbkdf2 "password" "salt" 1 20 "sha1")))

(provide 'nettle)
;;; nettle.el ends here

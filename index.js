const { KmsKeyringNode } = require("@aws-crypto/client-node");
const awsCrypto = require("@aws-crypto/client-node");
require("dotenv").config();

const awsEncryptionClient = awsCrypto.buildClient(
  awsCrypto.CommitmentPolicy.REQUIRE_ENCRYPT_REQUIRE_DECRYPT
);
const generatorKeyId = process.env.GENERATOR_KEY_ID;
const keyIds = [process.env.KEY_IDS];
const keyRing = new KmsKeyringNode({ generatorKeyId, keyIds });

encryptData = async (data, context) => {
  try {
    const { result } = await awsEncryptionClient.encrypt(keyRing, data, {
      encryptionContext: context,
    });
    return result.toString("base64");
  } catch (err) {
    console.log("Encryption error: ", err);
    throw err;
  }
};

decryptData = async (encryptedData, context) => {
  try {
    const encryptedBuffer = Buffer.from(encryptedData, "base64");
    const { plaintext, messageHeader } = await awsEncryptionClient.decrypt(
      keyRing,
      encryptedBuffer
    );
    Object.entries(context).forEach(([key, value]) => {
      if (messageHeader.encryptionContext[key] === value) {
        console.log("It matched.");
      } else {
        throw new Error("Encryption Context does not match expected value!");
      }
    });

    return plaintext.toString("utf8");
  } catch (err) {
    console.log("Decryption error: ", err);
    throw err;
  }
};

async function init() {
  let plainText = "Sensitive Data Test";
  console.log("==== Original Text ====");
  console.log(plainText);

  const context = {
    stage: "AWS KMS test",
    purpose: "test",
    orgin: "us-east-1",
  };

  // Encryption
  let encryptedData = await encryptData(plainText, context);
  console.log("==== Encrypted Data ====");
  console.log(encryptedData);

  // Decryption
  let decryptedData = await decryptData(encryptedData, context);
  console.log("==== Decrypted Data ====");
  console.log(decryptedData);
}

init();

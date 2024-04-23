import {
  LitAuthClient,
} from "@lit-protocol/lit-auth-client/src/index.js";
import prompts from "prompts";
import * as stytch from "stytch";
import { LitNodeClientNodeJs } from "@lit-protocol/lit-node-client-nodejs";
import { ProviderType } from "@lit-protocol/constants";
import { LitAbility, LitPKPResource, LitActionResource } from "@lit-protocol/auth-helpers";

//@ts-ignore
const ls = await import('node-localstorage');

/**
 * Should be defined in your local enviorment before running
 * see here: https://stytch.com/docs for setting up your stytch project
 */
const STYTCH_PROJECT_ID: string | undefined = process.env.STYTCH_PROJECT_ID;
const STYTCH_SECRET: string | undefined = process.env.STYTCH_SECRET;
const LIT_RELAY_API_KEY: string | undefined = process.env.LIT_RELAY_API_KEY;

if (!STYTCH_PROJECT_ID || !STYTCH_SECRET) {
  throw Error("Could not find stytch project secret or id in enviorment");
}

if (process.argv.length < 2) {
  throw Error("Please provide either --lookup or --claim flag");
}

const client = new stytch.Client({
  project_id: STYTCH_PROJECT_ID,
  secret: STYTCH_SECRET,
});

const emailResponse = await prompts({
  type: "text",
  name: "email",
  message: "Enter your email address",
});

const stytchResponse = await client.otps.email.loginOrCreate({
  email: emailResponse.email,
});

const otpResponse = await prompts({
  type: "text",
  name: "code",
  message: "Enter the code sent to your email:",
});

const authResponse = await client.otps.authenticate({
  method_id: stytchResponse.email_id,
  code: otpResponse.code,
  session_duration_minutes: 60 * 24 * 7,
});

let sessionResp = await client.sessions.get({
  user_id: authResponse.user_id,
});

const sessionStatus = await client.sessions.authenticate({
  session_token: authResponse.session_token,
});

const litNodeClient = new LitNodeClientNodeJs({
  litNetwork: "cayenne",
  debug: true,
  storageProvider: {
    provider: new ls.LocalStorage('./storage.db')
  }
});

await litNodeClient.connect();

const authClient = new LitAuthClient({
  litRelayConfig: {
    relayApiKey: LIT_RELAY_API_KEY,
  },
  litNodeClient,
});

const session = authClient.initProvider(
  ProviderType.StytchEmailFactorOtp,
  {
    userId: sessionStatus.session.user_id,
    appId: STYTCH_PROJECT_ID,
  }
);

const authMethod = await session.authenticate({
  accessToken: sessionStatus.session_jwt,
});
const publicKey = await session.computePublicKeyFromAuthMethod(authMethod);
console.log("local public key computed: ", publicKey);

if (process.argv.includes("--claim")) {
  let claimResp = await session.claimKeyId({
    authMethod,
  });

  console.log("claim response public key: ", claimResp.pubkey);
  const pkpInfo = await session.fetchPKPsThroughRelayer(authMethod);
  let matchingKey = pkpInfo.filter((info) => info.publicKey.replace('0x', '') === publicKey);
  console.log("matching key from relayer look up: ", matchingKey);
  const authNeededCallback = async (params: any) => {
    const response = await litNodeClient.signSessionKey({
      statement: params.statement,
      authMethods: [
        authMethod
      ],
      chainId: 1,
      pkpPublicKey: `0x${publicKey}`,
      resources: params.resources 
    });
    return response.authSig;
  };
  const signatures = await session.getSessionSigs({
    pkpPublicKey: `0x${publicKey}`,
    authMethod,
    //@ts-ignore
    sessionSigsParams: {
      chain: "ethereum",
      authNeededCallback,
      resourceAbilityRequests: [
        {
          resource: new LitPKPResource("*"),
          ability: LitAbility.PKPSigning,
        },
      ],
    },
  });
  console.log(signatures);

  const res = await litNodeClient.pkpSign({
    pubKey: `0x${publicKey}`,
    toSign: new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode("Hello world"))),
    sessionSigs: signatures
  });

  console.log(res);
  process.exit(0);
} else if (process.argv.length >= 2 && process.argv.includes("--lookup")) {
  const pkpInfo = await session.fetchPKPsThroughRelayer(authMethod);
  console.log("pkp info resolved: ", pkpInfo);
  let matchingKey = pkpInfo.filter((info) => info.publicKey.replace('0x', '') === publicKey);
  console.log("matching key from relayer look up: ", matchingKey);
  const authNeededCallback = async (params: any) => {
    const response = await litNodeClient.signSessionKey({
      statement: params.statement,
      authMethods: [
        authMethod
      ],
      chainId: 1,
      pkpPublicKey: `0x${publicKey}`,
      resources: params.resources
    });
    return response.authSig;
  };
  const signatures = await litNodeClient.getSessionSigs(
    //@ts-ignore
    {
    chain: "ethereum",
    authNeededCallback,
    resourceAbilityRequests: [
      {
        resource: new LitActionResource("*"),
        ability: LitAbility.PKPSigning,
      },
    ]
  });
  console.log(signatures);

  const res = await litNodeClient.pkpSign({
    pubKey: `0x${publicKey}`,
    toSign: new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode("Hello world"))),
    sessionSigs: signatures
  });
  process.exit(0);
} 


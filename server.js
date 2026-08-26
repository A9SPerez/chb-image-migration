import express from "express";
import cookieParser from "cookie-parser";
import crypto from "crypto";
import manifest from "./media-manifest.json" with { type: "json" };

const app = express();
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(cookieParser());

const PORT = process.env.PORT || 3000;
const CLIENT_ID = process.env.SHOPIFY_CLIENT_ID;
const CLIENT_SECRET = process.env.SHOPIFY_CLIENT_SECRET;
const APP_URL = (process.env.APP_URL || "").replace(/\/$/, "");
const API_VERSION = process.env.SHOPIFY_API_VERSION || "2026-07";
const SCOPES = process.env.SHOPIFY_SCOPES || "read_products,write_products";
const ALLOWED_SHOP = (process.env.ALLOWED_SHOP || "").toLowerCase();

if (!CLIENT_ID || !CLIENT_SECRET || !APP_URL) {
  console.warn("Missing SHOPIFY_CLIENT_ID, SHOPIFY_CLIENT_SECRET, or APP_URL.");
}

// One-time migration tool: tokens are kept only in memory.
// If Render restarts, simply authorize again.
const tokens = new Map();

function validShop(shop) {
  if (!shop || typeof shop !== "string") return false;
  const s = shop.toLowerCase();
  if (!/^[a-z0-9][a-z0-9-]*\.myshopify\.com$/.test(s)) return false;
  return !ALLOWED_SHOP || s === ALLOWED_SHOP;
}

function hmacValid(query) {
  const provided = query.hmac;
  if (!provided || !CLIENT_SECRET) return false;

  const pairs = Object.keys(query)
    .filter((k) => k !== "hmac" && k !== "signature")
    .sort()
    .map((k) => `${k}=${Array.isArray(query[k]) ? query[k].join(",") : query[k]}`);

  const message = pairs.join("&");
  const digest = crypto.createHmac("sha256", CLIENT_SECRET).update(message).digest("hex");

  try {
    return crypto.timingSafeEqual(Buffer.from(digest, "utf8"), Buffer.from(provided, "utf8"));
  } catch {
    return false;
  }
}

function page(title, body) {
  return `<!doctype html>
  <html>
  <head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width,initial-scale=1">
    <title>${title}</title>
    <style>
      body{font-family:system-ui,-apple-system,Segoe UI,Roboto,sans-serif;max-width:920px;margin:40px auto;padding:0 20px;color:#171717}
      .card{border:1px solid #ddd;border-radius:14px;padding:22px;margin:18px 0}
      button,.button{background:#111;color:#fff;border:0;border-radius:9px;padding:11px 16px;text-decoration:none;display:inline-block;cursor:pointer}
      button.secondary,.secondary{background:#eee;color:#111}
      table{border-collapse:collapse;width:100%;font-size:14px} td,th{border-bottom:1px solid #eee;padding:8px;text-align:left}
      .ok{color:#0a7a35}.warn{color:#a05a00}.bad{color:#b00020}
      code{background:#f4f4f4;padding:2px 5px;border-radius:4px}
    </style>
  </head>
  <body>${body}</body></html>`;
}

app.get("/health", (_req, res) => {
  res.json({ ok: true, app: "CHB Image Migration" });
});

app.get("/", (req, res) => {
  const shop = String(req.query.shop || ALLOWED_SHOP || "").toLowerCase();

  if (!validShop(shop)) {
    return res.status(400).send(page("CHB Image Migration", `
      <h1>CHB Image Migration</h1>
      <div class="card">
        <p>Missing or invalid Shopify shop domain.</p>
        <p>Open this app from Shopify Admin, or use <code>?shop=your-store.myshopify.com</code>.</p>
      </div>`));
  }

  if (!tokens.has(shop)) {
    return res.send(page("CHB Image Migration", `
      <h1>CHB Image Migration</h1>
      <div class="card">
        <p>Shop: <strong>${shop}</strong></p>
        <p>This tool only adds product media. It does not change variants, prices, inventory, status, or collections.</p>
        <a class="button" target="_top" rel="noopener "href="/auth?shop=${encodeURIComponent(shop)}">Authorize Shopify</a>
      </div>`));
  }

  const total = manifest.length;
  return res.send(page("CHB Image Migration", `
    <h1>CHB Image Migration</h1>
    <div class="card">
      <p><strong>Authorized:</strong> ${shop}</p>
      <p><strong>Manifest:</strong> ${total} product/image associations.</p>
      <p>Default safety rule: products that already have Shopify media are skipped.</p>
    </div>

    <div class="card">
      <h2>1. Dry run</h2>
      <p>Checks handles and current media without changing anything.</p>
      <form method="post" action="/dry-run">
        <input type="hidden" name="shop" value="${shop}">
        <button type="submit">Run dry check</button>
      </form>
    </div>

    <div class="card">
      <h2>2. Test one product</h2>
      <p>Tests only <strong>Finale Verde Set</strong>. If it already has media, the app skips it.</p>
      <form method="post" action="/migrate-one">
        <input type="hidden" name="shop" value="${shop}">
        <input type="hidden" name="handle" value="pre-order-finale-verde-set">
        <button type="submit">Test Finale Verde Set</button>
      </form>
    </div>

    <div class="card">
      <h2>3. Migrate missing primary images</h2>
      <p>Adds media only to products that currently have zero media in Shopify.</p>
      <form method="post" action="/migrate-all" onsubmit="return confirm('Run the media-only migration for products with no media?');">
        <input type="hidden" name="shop" value="${shop}">
        <button type="submit">Migrate missing images</button>
      </form>
    </div>
  `));
});

app.get("/auth", (req, res) => {
  const shop = String(req.query.shop || "").toLowerCase();
  if (!validShop(shop)) return res.status(400).send("Invalid shop");

  const state = crypto.randomBytes(24).toString("hex");
  res.cookie("shopify_oauth_state", state, {
    httpOnly: true,
    secure: true,
    sameSite: "lax",
    maxAge: 10 * 60 * 1000
  });

  const redirectUri = `${APP_URL}/auth/callback`;
  const url = new URL(`https://${shop}/admin/oauth/authorize`);
  url.searchParams.set("client_id", CLIENT_ID);
  url.searchParams.set("scope", SCOPES);
  url.searchParams.set("redirect_uri", redirectUri);
  url.searchParams.set("state", state);

  res.redirect(url.toString());
});

app.get("/auth/callback", async (req, res) => {
  const { shop, code, state } = req.query;

  if (!validShop(shop)) return res.status(400).send("Invalid shop");
  if (!code || !state || state !== req.cookies.shopify_oauth_state) {
    return res.status(400).send("Invalid OAuth state");
  }
  if (!hmacValid(req.query)) {
    return res.status(400).send("Invalid Shopify HMAC");
  }

  try {
    const response = await fetch(`https://${shop}/admin/oauth/access_token`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        client_id: CLIENT_ID,
        client_secret: CLIENT_SECRET,
        code
      })
    });

    const data = await response.json();
    if (!response.ok || !data.access_token) {
      return res.status(500).send(page("Authorization failed", `<h1>Authorization failed</h1><pre>${escapeHtml(JSON.stringify(data, null, 2))}</pre>`));
    }

    tokens.set(shop.toLowerCase(), data.access_token);
    res.clearCookie("shopify_oauth_state");
    return res.redirect(`/?shop=${encodeURIComponent(shop)}`);
  } catch (e) {
    return res.status(500).send(page("Authorization failed", `<h1>Authorization failed</h1><pre>${escapeHtml(String(e))}</pre>`));
  }
});

function escapeHtml(s) {
  return String(s)
    .replaceAll("&", "&amp;").replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;").replaceAll('"', "&quot;");
}

async function gql(shop, query, variables = {}) {
  const token = tokens.get(shop.toLowerCase());
  if (!token) throw new Error("Shop not authorized");

  const r = await fetch(`https://${shop}/admin/api/${API_VERSION}/graphql.json`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "X-Shopify-Access-Token": token
    },
    body: JSON.stringify({ query, variables })
  });

  const json = await r.json();
  if (!r.ok) throw new Error(`GraphQL HTTP ${r.status}: ${JSON.stringify(json)}`);
  if (json.errors?.length) throw new Error(`GraphQL errors: ${JSON.stringify(json.errors)}`);
  return json.data;
}

async function getProduct(shop, handle) {
  const data = await gql(shop, `
    query GetProduct($handle: String!) {
      productByHandle(handle: $handle) {
        id
        title
        handle
        media(first: 10) {
          nodes {
            id
            mediaContentType
            status
          }
        }
      }
    }`, { handle });

  return data.productByHandle;
}

function filenameFromUrl(url, fallback = "product-image") {
  try {
    const pathname = new URL(url).pathname;
    const name = decodeURIComponent(
      pathname.split("/").pop() || ""
    ).trim();

    return name || fallback;
  } catch {
    return fallback;
  }
}

function detectImageFormat(bytes, headerContentType = "") {
  const b = new Uint8Array(bytes);

  // JPEG
  if (
    b.length >= 3 &&
    b[0] === 0xff &&
    b[1] === 0xd8 &&
    b[2] === 0xff
  ) {
    return {
      mimeType: "image/jpeg",
      extension: ".jpg",
      format: "JPEG"
    };
  }

  // PNG
  if (
    b.length >= 8 &&
    b[0] === 0x89 &&
    b[1] === 0x50 &&
    b[2] === 0x4e &&
    b[3] === 0x47 &&
    b[4] === 0x0d &&
    b[5] === 0x0a &&
    b[6] === 0x1a &&
    b[7] === 0x0a
  ) {
    return {
      mimeType: "image/png",
      extension: ".png",
      format: "PNG"
    };
  }

  // GIF
  if (
    b.length >= 6 &&
    b[0] === 0x47 &&
    b[1] === 0x49 &&
    b[2] === 0x46 &&
    b[3] === 0x38
  ) {
    return {
      mimeType: "image/gif",
      extension: ".gif",
      format: "GIF"
    };
  }

  // WEBP: RIFF....WEBP
  if (
    b.length >= 12 &&
    b[0] === 0x52 &&
    b[1] === 0x49 &&
    b[2] === 0x46 &&
    b[3] === 0x46 &&
    b[8] === 0x57 &&
    b[9] === 0x45 &&
    b[10] === 0x42 &&
    b[11] === 0x50
  ) {
    return {
      mimeType: "image/webp",
      extension: ".webp",
      format: "WEBP"
    };
  }

  throw new Error(
    `Unsupported or unrecognized image format. GoDaddy Content-Type: ${headerContentType || "unknown"}`
  );
}

function normalizeFilename(originalName, extension, fallback) {
  const base = String(originalName || fallback || "product-image")
    .replace(/\.[a-zA-Z0-9]+$/, "")
    .replace(/[^a-zA-Z0-9._-]+/g, "-");

  return `${base}${extension}`;
}

async function downloadSourceImage(item) {
  const response = await fetch(item.sourceUrl, {
    redirect: "follow",
    headers: {
      "User-Agent": "Mozilla/5.0 CHB-Image-Migration/1.0",
      Accept: "image/avif,image/webp,image/apng,image/*,*/*;q=0.8"
    }
  });

  if (!response.ok) {
    throw new Error(
      `Source image download failed (${response.status}) for ${item.sourceUrl}`
    );
  }

  const headerContentType =
    response.headers.get("content-type") || "";

  const bytes = await response.arrayBuffer();

  if (!bytes.byteLength) {
    throw new Error("Downloaded source image is empty.");
  }

  const detected = detectImageFormat(
    bytes,
    headerContentType
  );

  const originalName = filenameFromUrl(
    item.sourceUrl,
    item.handle
  );

  const filename = normalizeFilename(
    originalName,
    detected.extension,
    item.handle
  );

  return {
    filename,
    mimeType: detected.mimeType,
    format: detected.format,
    bytes,
    byteLength: bytes.byteLength,
    sourceContentType: headerContentType
  };
}

async function createStagedProductImageTarget(shop, file) {
  const data = await gql(
    shop,
    `
    mutation StagedProductImage($input: [StagedUploadInput!]!) {
      stagedUploadsCreate(input: $input) {
        stagedTargets {
          url
          resourceUrl
          parameters {
            name
            value
          }
        }
        userErrors {
          field
          message
        }
      }
    }
    `,
    {
      input: [
        {
          filename: file.filename,
          mimeType: file.mimeType,
          fileSize: String(file.byteLength),
          httpMethod: "POST",
          resource: "PRODUCT_IMAGE"
        }
      ]
    }
  );

  const result = data.stagedUploadsCreate;

  if (result.userErrors?.length) {
    throw new Error(
      `stagedUploadsCreate: ${result.userErrors
        .map((e) => e.message)
        .join("; ")}`
    );
  }

  const target = result.stagedTargets?.[0];

  if (!target?.url || !target?.resourceUrl) {
    throw new Error(
      "Shopify did not return a staged upload target."
    );
  }

  return target;
}

async function uploadToStagedTarget(target, file) {
  const form = new FormData();

  for (const p of target.parameters || []) {
    form.append(p.name, p.value);
  }

  form.append(
    "file",
    new Blob(
      [file.bytes],
      { type: file.mimeType }
    ),
    file.filename
  );

  const response = await fetch(target.url, {
    method: "POST",
    body: form
  });

  if (!response.ok) {
    const body = await response
      .text()
      .catch(() => "");

    throw new Error(
      `Staged upload failed (${response.status}): ${body.slice(0, 500)}`
    );
  }
}

async function attachStagedImageToProduct(
  shop,
  product,
  item,
  resourceUrl
) {
  const data = await gql(
    shop,
    `
    mutation AddMedia(
      $product: ProductUpdateInput!,
      $media: [CreateMediaInput!]
    ) {
      productUpdate(product: $product, media: $media) {
        product {
          id
          title
          handle
        }
        userErrors {
          field
          message
        }
      }
    }
    `,
    {
      product: {
        id: product.id
      },
      media: [
        {
          originalSource: resourceUrl,
          mediaContentType: "IMAGE",
          alt: item.productName
        }
      ]
    }
  );

  const result = data.productUpdate;

  if (result.userErrors?.length) {
    throw new Error(
      `productUpdate: ${result.userErrors
        .map((e) => e.message)
        .join("; ")}`
    );
  }

  return result.product;
}

async function addImage(shop, product, item) {
  const file = await downloadSourceImage(item);

  console.log(
    `CHB image diagnostic: ${item.productName} | ` +
    `${file.format} | ${file.mimeType} | ` +
    `${file.filename} | ${file.byteLength} bytes | ` +
    `source Content-Type: ${file.sourceContentType}`
  );

  console.log("STEP 1: requesting Shopify staged upload target");

  const target =
    await createStagedProductImageTarget(
      shop,
      file
    );

  console.log(
    `STEP 2: staged target received | resourceUrl: ${target.resourceUrl}`
  );

  await uploadToStagedTarget(
    target,
    file
  );

  console.log("STEP 3: file uploaded to Shopify staged storage");

  const productResult =
    await attachStagedImageToProduct(
      shop,
      product,
      item,
      target.resourceUrl
    );

  console.log("STEP 4: staged image attached to product");

  return {
    product: productResult,
    diagnostic: {
      format: file.format,
      mimeType: file.mimeType,
      filename: file.filename,
      bytes: file.byteLength,
      sourceContentType: file.sourceContentType
    }
  };
}
  

app.post("/dry-run", async (req, res) => {
  const shop = String(req.body.shop || "").toLowerCase();
  if (!validShop(shop) || !tokens.has(shop)) return res.status(401).send("Authorize first");

  const rows = [];
  for (const item of manifest) {
    try {
      const p = await getProduct(shop, item.handle);
      rows.push({
        name: item.productName,
        handle: item.handle,
        found: !!p,
        mediaCount: p?.media?.nodes?.length ?? 0
      });
    } catch (e) {
      rows.push({ name: item.productName, handle: item.handle, found: false, mediaCount: "ERR", error: String(e) });
    }
  }

  const found = rows.filter(r => r.found).length;
  const noMedia = rows.filter(r => r.found && r.mediaCount === 0).length;

  const table = rows.map(r => `<tr>
    <td>${escapeHtml(r.name)}</td><td><code>${escapeHtml(r.handle)}</code></td>
    <td>${r.found ? '<span class="ok">Yes</span>' : '<span class="bad">No</span>'}</td>
    <td>${escapeHtml(r.mediaCount)}</td>
  </tr>`).join("");

  res.send(page("Dry run", `
    <h1>Dry run</h1>
    <div class="card"><p>Found: <strong>${found}/${rows.length}</strong></p><p>Products with zero media: <strong>${noMedia}</strong></p></div>
    <div class="card"><table><thead><tr><th>Product</th><th>Handle</th><th>Found</th><th>Current media</th></tr></thead><tbody>${table}</tbody></table></div>
    <a class="button secondary" href="/?shop=${encodeURIComponent(shop)}">Back</a>
  `));
});

app.post("/migrate-one", async (req, res) => {
  const shop = String(req.body.shop || "").toLowerCase();
  const handle = String(req.body.handle || "");
  if (!validShop(shop) || !tokens.has(shop)) return res.status(401).send("Authorize first");

  const item = manifest.find(x => x.handle === handle);
  if (!item) return res.status(404).send("Manifest item not found");

  try {
    const p = await getProduct(shop, handle);
    if (!p) throw new Error("Product not found in Shopify");
    if (
  (p.media?.nodes || []).some(
    (media) => media.status !== "FAILED"
  )
) {
      return res.send(page("Test skipped", `
        <h1>Test skipped safely</h1>
        <div class="card"><p>${escapeHtml(p.title)} already has Shopify media, so nothing was changed.</p></div>
        <a class="button secondary" href="/?shop=${encodeURIComponent(shop)}">Back</a>`));
    }

    await addImage(shop, p, item);
    return res.send(page("Test started", `
      <h1>Test image submitted</h1>
      <div class="card">
        <p>Product: <strong>${escapeHtml(p.title)}</strong></p>
        <p>Shopify accepted the media request. Image processing can take a short time.</p>
        <p>No variants, prices, inventory, status, or collections were changed.</p>
      </div>
      <a class="button secondary" href="/?shop=${encodeURIComponent(shop)}">Back</a>`));
  } catch (e) {
    return res.status(500).send(page("Test failed", `<h1>Test failed</h1><div class="card"><pre>${escapeHtml(String(e))}</pre></div>`));
  }
});

app.post("/migrate-all", async (req, res) => {
  const shop = String(req.body.shop || "").toLowerCase();
  if (!validShop(shop) || !tokens.has(shop)) return res.status(401).send("Authorize first");

  const results = [];
  for (const item of manifest) {
    try {
      const p = await getProduct(shop, item.handle);
      if (!p) {
        results.push({ name: item.productName, status: "NOT_FOUND" });
        continue;
      }
      if (
  (p.media?.nodes || []).some(
    (media) => media.status !== "FAILED"
  )
) {
        results.push({ name: item.productName, status: "SKIPPED_HAS_MEDIA" });
        continue;
      }
      await addImage(shop, p, item);
      results.push({ name: item.productName, status: "SUBMITTED" });

      // Gentle pacing for Shopify and the remote image host.
      await new Promise(r => setTimeout(r, 350));
    } catch (e) {
      results.push({ name: item.productName, status: "ERROR", error: String(e) });
    }
  }

  const counts = results.reduce((a, r) => {
    a[r.status] = (a[r.status] || 0) + 1;
    return a;
  }, {});

  const table = results.map(r => `<tr>
    <td>${escapeHtml(r.name)}</td><td>${escapeHtml(r.status)}</td><td>${escapeHtml(r.error || "")}</td>
  </tr>`).join("");

  res.send(page("Migration results", `
    <h1>Migration results</h1>
    <div class="card"><pre>${escapeHtml(JSON.stringify(counts, null, 2))}</pre></div>
    <div class="card"><table><thead><tr><th>Product</th><th>Status</th><th>Error</th></tr></thead><tbody>${table}</tbody></table></div>
    <a class="button secondary" href="/?shop=${encodeURIComponent(shop)}">Back</a>
  `));
});
app.get("/discover-godaddy", async (_req, res) => {
  try {
    const siteUrl = "https://callherbronzeada.com/";

    const siteResponse = await fetch(siteUrl, {
      redirect: "follow",
      headers: {
        "User-Agent": "Mozilla/5.0 CHB-Image-Migration/1.0",
        "Accept": "text/html,*/*"
      }
    });

    const html = await siteResponse.text();

    const rawScriptUrls = [
      ...html.matchAll(
        /<script[^>]+src=["']([^"']+)["']/gi
      )
    ].map((m) => m[1]);

    const scriptUrls = [...new Set(rawScriptUrls)]
      .map((src) => {
        try {
          return new URL(src, siteUrl).href;
        } catch {
          return null;
        }
      })
      .filter(Boolean);

    const scriptReports = [];

    for (const scriptUrl of scriptUrls) {
      try {
        const scriptResponse = await fetch(scriptUrl, {
          redirect: "follow",
          headers: {
            "User-Agent": "Mozilla/5.0 CHB-Image-Migration/1.0",
            "Accept": "*/*"
          }
        });

        const text = await scriptResponse.text();
        const lower = text.toLowerCase();

        const keywords = [
          "product",
          "products",
          "catalog",
          "commerce",
          "gallery",
          "images",
          "imageurl",
          "productid",
          "product_id",
          "/api/",
          "graphql",
          "storefront",
          "inventory"
        ];

        const matches = [];

        for (const keyword of keywords) {
          let start = 0;
          let count = 0;

          while (count < 15) {
            const pos = lower.indexOf(
              keyword.toLowerCase(),
              start
            );

            if (pos === -1) break;

            matches.push({
              keyword,
              position: pos,
              fragment: text.slice(
                Math.max(0, pos - 500),
                Math.min(text.length, pos + 1200)
              )
            });

            start = pos + keyword.length;
            count++;
          }
        }

        const urls = [
          ...text.matchAll(
            /https?:\/\/[^"'`\\\s<>]+/g
          )
        ].map((m) => m[0]);

        scriptReports.push({
          scriptUrl,
          status: scriptResponse.status,
          length: text.length,
          possibleUrls: [...new Set(urls)].slice(0, 200),
          matches: matches.slice(0, 150)
        });
      } catch (e) {
        scriptReports.push({
          scriptUrl,
          error: String(e)
        });
      }
    }

    const report = {
      websiteStatus: siteResponse.status,
      htmlLength: html.length,
      scriptCount: scriptUrls.length,
      scriptUrls,
      scriptReports
    };

    res
      .type("text/plain")
      .send(JSON.stringify(report, null, 2));
  } catch (e) {
    res
      .status(500)
      .type("text/plain")
      .send(String(e));
  }
});
app.get("/inspect-products-module", async (_req, res) => {
  try {
    const siteUrl = "https://callherbronzeada.com/";

    const siteResponse = await fetch(siteUrl, {
      redirect: "follow",
      headers: {
        "User-Agent": "Mozilla/5.0 CHB-Image-Migration/1.0",
        "Accept": "text/html,*/*"
      }
    });

    const html = await siteResponse.text();

    const rawScriptUrls = [
      ...html.matchAll(
        /<script[^>]+src=["']([^"']+)["']/gi
      )
    ].map((m) => m[1]);

    const scriptUrls = [...new Set(rawScriptUrls)]
      .map((src) => {
        try {
          return new URL(src, siteUrl).href;
        } catch {
          return null;
        }
      })
      .filter(Boolean);

    const discoveries = [];

    for (const scriptUrl of scriptUrls) {
      try {
        const scriptResponse = await fetch(scriptUrl, {
          redirect: "follow",
          headers: {
            "User-Agent": "Mozilla/5.0 CHB-Image-Migration/1.0",
            "Accept": "*/*"
          }
        });

        const text = await scriptResponse.text();

        const productModuleNames = [
          ...text.matchAll(
            /products-[a-zA-Z0-9_-]+\.js/g
          )
        ].map((m) => m[0]);

        for (const moduleName of [...new Set(productModuleNames)]) {
          const possibleBases = [
            new URL(scriptUrl),
            new URL(siteUrl)
          ];

          for (const base of possibleBases) {
            try {
              const moduleUrl = new URL(
                moduleName,
                base
              ).href;

              const moduleResponse = await fetch(moduleUrl, {
                redirect: "follow",
                headers: {
                  "User-Agent":
                    "Mozilla/5.0 CHB-Image-Migration/1.0",
                  "Accept": "*/*"
                }
              });

              const moduleText =
                await moduleResponse.text();

              if (!moduleResponse.ok) {
                discoveries.push({
                  moduleName,
                  moduleUrl,
                  status: moduleResponse.status
                });
                continue;
              }

              const lower = moduleText.toLowerCase();

              const keywords = [
                "fetch(",
                "axios",
                "productid",
                "productinstanceid",
                "images",
                "gallery",
                "media",
                "catalog",
                "inventory",
                "graphql",
                "query",
                "endpoint",
                "url",
                "wsimg"
              ];

              const matches = [];

              for (const keyword of keywords) {
                let start = 0;
                let count = 0;

                while (count < 25) {
                  const pos = lower.indexOf(
                    keyword.toLowerCase(),
                    start
                  );

                  if (pos === -1) break;

                  matches.push({
                    keyword,
                    position: pos,
                    fragment: moduleText.slice(
                      Math.max(0, pos - 700),
                      Math.min(
                        moduleText.length,
                        pos + 1800
                      )
                    )
                  });

                  start = pos + keyword.length;
                  count++;
                }
              }

              const urls = [
                ...moduleText.matchAll(
                  /https?:\/\/[^"'`\\\s<>]+/g
                )
              ].map((m) => m[0]);

              discoveries.push({
                moduleName,
                moduleUrl,
                status: moduleResponse.status,
                length: moduleText.length,
                possibleUrls: [
                  ...new Set(urls)
                ].slice(0, 300),
                matches: matches.slice(0, 250)
              });
            } catch (e) {
              discoveries.push({
                moduleName,
                error: String(e)
              });
            }
          }
        }
      } catch (e) {
        discoveries.push({
          scriptUrl,
          error: String(e)
        });
      }
    }

    res
      .type("text/plain")
      .send(
        JSON.stringify(
          {
            count: discoveries.length,
            discoveries
          },
          null,
          2
        )
      );
  } catch (e) {
    res
      .status(500)
      .type("text/plain")
      .send(String(e));
  }
});
app.get("/inspect-product-chunk-mapping", async (_req, res) => {
  try {
    const siteUrl = "https://callherbronzeada.com/";

    const siteResponse = await fetch(siteUrl, {
      redirect: "follow",
      headers: {
        "User-Agent": "Mozilla/5.0 CHB-Image-Migration/1.0",
        "Accept": "text/html,*/*"
      }
    });

    const html = await siteResponse.text();

    const rawScriptUrls = [
      ...html.matchAll(
        /<script[^>]+src=["']([^"']+)["']/gi
      )
    ].map((m) => m[1]);

    const scriptUrls = [...new Set(rawScriptUrls)]
      .map((src) => {
        try {
          return new URL(src, siteUrl).href;
        } catch {
          return null;
        }
      })
      .filter(Boolean);

    const targets = [
      "products-a9c171ea.js",
      "products-6af415ef.js",
      "products-15f07efe.js"
    ];

    const findings = [];

    for (const scriptUrl of scriptUrls) {
      try {
        const scriptResponse = await fetch(scriptUrl, {
          redirect: "follow",
          headers: {
            "User-Agent":
              "Mozilla/5.0 CHB-Image-Migration/1.0",
            "Accept": "*/*"
          }
        });

        const text = await scriptResponse.text();

        for (const target of targets) {
          let start = 0;
          let count = 0;

          while (count < 20) {
            const pos = text.indexOf(target, start);

            if (pos === -1) break;

            findings.push({
              scriptUrl,
              target,
              position: pos,
              fragment: text.slice(
                Math.max(0, pos - 3000),
                Math.min(text.length, pos + 5000)
              )
            });

            start = pos + target.length;
            count++;
          }
        }
      } catch (e) {
        findings.push({
          scriptUrl,
          error: String(e)
        });
      }
    }

    res
      .type("text/plain")
      .send(
        JSON.stringify(
          {
            targetCount: targets.length,
            findingCount: findings.length,
            findings
          },
          null,
          2
        )
      );
  } catch (e) {
    res
      .status(500)
      .type("text/plain")
      .send(String(e));
  }
}); 
app.get("/gallery-dry-run-one", async (req, res) => {
  try {
    const shop = String(
      req.query.shop || ALLOWED_SHOP || ""
    ).toLowerCase();

    if (!validShop(shop) || !tokens.has(shop)) {
      return res
        .status(401)
        .send("Authorize Shopify first");
    }

    const handle = "pre-order-finale-verde-set";

    const godaddyUrl =
      "https://b54aa1d3-662e-49ee-b390-0d4ebb6dcdbe.mysimplestore.com" +
      "/api/v2/products/" +
      encodeURIComponent(handle) +
      "?app=vnext";

    const sourceResponse = await fetch(godaddyUrl, {
      headers: {
        "User-Agent":
          "Mozilla/5.0 CHB-Image-Migration/1.0",
        "Accept": "application/json"
      }
    });

    if (!sourceResponse.ok) {
      throw new Error(
        `GoDaddy product API failed: ${sourceResponse.status}`
      );
    }

    const sourceProduct = await sourceResponse.json();

    const sourceImages = (sourceProduct.assets || [])
      .filter(
        (asset) =>
          asset &&
          asset.type === "image" &&
          asset.original_url
      )
      .map((asset, index) => ({
        position: index + 1,
        url: asset.original_url,
        width: asset.attachment_width || "",
        height: asset.attachment_height || ""
      }));

    const shopifyProduct = await getProduct(
      shop,
      handle
    );

    if (!shopifyProduct) {
      throw new Error(
        "Product not found in Shopify"
      );
    }

    const shopifyMedia =
      shopifyProduct.media?.nodes || [];

    const rows = sourceImages
      .map(
        (image) => `
          <tr>
            <td>${image.position}</td>
            <td>${escapeHtml(
              `${image.width} x ${image.height}`
            )}</td>
            <td>
              <code>${escapeHtml(image.url)}</code>
            </td>
          </tr>
        `
      )
      .join("");

    return res.send(
      page(
        "Gallery dry run",
        `
          <h1>Gallery dry run — Finale Verde Set</h1>

          <div class="card">
            <p>
              <strong>GoDaddy source images:</strong>
              ${sourceImages.length}
            </p>

            <p>
              <strong>Current Shopify media:</strong>
              ${shopifyMedia.length}
            </p>

            <p>
              <strong>Images apparently missing:</strong>
              ${Math.max(
                0,
                sourceImages.length -
                  shopifyMedia.length
              )}
            </p>

            <p>
              Nothing was changed.
            </p>
          </div>

          <div class="card">
            <table>
              <thead>
                <tr>
                  <th>Position</th>
                  <th>Dimensions</th>
                  <th>Original URL</th>
                </tr>
              </thead>
              <tbody>
                ${rows}
              </tbody>
            </table>
          </div>

          <a
            class="button secondary"
            href="/?shop=${encodeURIComponent(shop)}"
          >
            Back
          </a>
        `
      )
    );
  } catch (e) {
    return res
      .status(500)
      .send(
        page(
          "Gallery dry run failed",
          `
            <h1>Gallery dry run failed</h1>
            <div class="card">
              <pre>${escapeHtml(String(e))}</pre>
            </div>
          `
        )
      );
  }
});
app.get("/gallery-migrate-one", async (req, res) => {
  try {
    const shop = String(
      req.query.shop || ALLOWED_SHOP || ""
    ).toLowerCase();

    if (!validShop(shop) || !tokens.has(shop)) {
      return res
        .status(401)
        .send("Authorize Shopify first");
    }

    const handle = "pre-order-finale-verde-set";
    const productName = "Finale Verde Set";

    const godaddyUrl =
      "https://b54aa1d3-662e-49ee-b390-0d4ebb6dcdbe.mysimplestore.com" +
      "/api/v2/products/" +
      encodeURIComponent(handle) +
      "?app=vnext";

    const sourceResponse = await fetch(godaddyUrl, {
      headers: {
        "User-Agent":
          "Mozilla/5.0 CHB-Image-Migration/1.0",
        "Accept": "application/json"
      }
    });

    if (!sourceResponse.ok) {
      throw new Error(
        `GoDaddy product API failed: ${sourceResponse.status}`
      );
    }

    const sourceProduct =
      await sourceResponse.json();

    const sourceImages = (sourceProduct.assets || [])
      .filter(
        (asset) =>
          asset &&
          asset.type === "image" &&
          asset.original_url
      )
      .map((asset, index) => ({
        position: index + 1,
        sourceUrl: String(asset.original_url)
          .split("/:/rs=")[0],
        productName,
        handle
      }));

    const shopifyProduct =
      await getProduct(shop, handle);

    if (!shopifyProduct) {
      throw new Error(
        "Finale Verde Set not found in Shopify"
      );
    }

    const currentMedia =
      (shopifyProduct.media?.nodes || [])
        .filter(
          (media) =>
            media.status !== "FAILED"
        );

    if (sourceImages.length !== 9) {
      throw new Error(
        `Safety stop: expected 9 source images but found ${sourceImages.length}`
      );
    }

    if (currentMedia.length !== 1) {
      throw new Error(
        `Safety stop: expected 1 current Shopify image but found ${currentMedia.length}`
      );
    }

    const imagesToAdd = sourceImages.slice(1);

    const results = [];

    for (const item of imagesToAdd) {
      try {
        console.log(
          `Gallery migration: ${productName} image ${item.position}/9`
        );

        await addImage(
          shop,
          shopifyProduct,
          item
        );

        results.push({
          position: item.position,
          status: "SUBMITTED"
        });

        await new Promise(
          (resolve) =>
            setTimeout(resolve, 500)
        );
      } catch (e) {
        results.push({
          position: item.position,
          status: "ERROR",
          error: String(e)
        });

        break;
      }
    }

    const submitted =
      results.filter(
        (r) => r.status === "SUBMITTED"
      ).length;

    const errors =
      results.filter(
        (r) => r.status === "ERROR"
      ).length;

    const rows = results
      .map(
        (r) => `
          <tr>
            <td>${r.position}</td>
            <td>${escapeHtml(r.status)}</td>
            <td>${escapeHtml(r.error || "")}</td>
          </tr>
        `
      )
      .join("");

    return res.send(
      page(
        "Finale Verde gallery migration",
        `
          <h1>Finale Verde gallery migration</h1>

          <div class="card">
            <p>
              <strong>Source images:</strong>
              ${sourceImages.length}
            </p>

            <p>
              <strong>Already in Shopify:</strong>
              1
            </p>

            <p>
              <strong>Submitted now:</strong>
              ${submitted}
            </p>

            <p>
              <strong>Errors:</strong>
              ${errors}
            </p>
          </div>

          <div class="card">
            <table>
              <thead>
                <tr>
                  <th>Position</th>
                  <th>Status</th>
                  <th>Error</th>
                </tr>
              </thead>
              <tbody>
                ${rows}
              </tbody>
            </table>
          </div>

          <a
            class="button secondary"
            href="/?shop=${encodeURIComponent(shop)}"
          >
            Back
          </a>
        `
      )
    );
  } catch (e) {
    return res
      .status(500)
      .send(
        page(
          "Gallery migration stopped",
          `
            <h1>Gallery migration stopped</h1>
            <div class="card">
              <pre>${escapeHtml(String(e))}</pre>
            </div>
          `
        )
      );
  }
});
app.get("/gallery-dry-run-all", async (req, res) => {
  try {
    const shop = String(
      req.query.shop || ALLOWED_SHOP || ""
    ).toLowerCase();

    if (!validShop(shop) || !tokens.has(shop)) {
      return res
        .status(401)
        .send("Authorize Shopify first");
    }

    const GODADDY_BASE =
      "https://b54aa1d3-662e-49ee-b390-0d4ebb6dcdbe.mysimplestore.com";

    // One entry per Shopify product handle.
    const productsByHandle = new Map();

    for (const item of manifest) {
      if (!productsByHandle.has(item.handle)) {
        productsByHandle.set(item.handle, {
          handle: item.handle,
          productName: item.productName
        });
      }
    }

    const products = [...productsByHandle.values()];
    const results = [];

    for (const item of products) {
      try {
        const godaddyUrl =
          `${GODADDY_BASE}/api/v2/products/` +
          `${encodeURIComponent(item.handle)}?app=vnext`;

        const sourceResponse = await fetch(godaddyUrl, {
          headers: {
            "User-Agent":
              "Mozilla/5.0 CHB-Image-Migration/1.0",
            "Accept": "application/json"
          }
        });

        if (!sourceResponse.ok) {
          results.push({
            name: item.productName,
            handle: item.handle,
            sourceImages: 0,
            shopifyMedia: "",
            missing: "",
            status:
              `SOURCE_API_${sourceResponse.status}`
          });
          continue;
        }

        const sourceProduct =
          await sourceResponse.json();

        const sourceImages =
          (sourceProduct.assets || []).filter(
            (asset) =>
              asset &&
              asset.type === "image" &&
              asset.original_url
          );

        const shopifyData = await gql(
  shop,
  `
    query GalleryDryRunProduct($handle: String!) {
      productByHandle(handle: $handle) {
        id
        title
        handle
        media(first: 100) {
          nodes {
            id
            status
            mediaContentType
          }
        }
      }
    }
  `,
  {
    handle: item.handle
  }
);

const shopifyProduct =
  shopifyData.productByHandle;

        if (!shopifyProduct) {
          results.push({
            name:
              sourceProduct.name ||
              item.productName,
            handle: item.handle,
            sourceImages: sourceImages.length,
            shopifyMedia: "",
            missing: "",
            status: "NOT_FOUND_IN_SHOPIFY"
          });
          continue;
        }

        const validMedia =
          (shopifyProduct.media?.nodes || [])
            .filter(
              (media) =>
                media.status !== "FAILED"
            );

        const sourceCount =
          sourceImages.length;

        const shopifyCount =
          validMedia.length;

        const missing =
          Math.max(
            0,
            sourceCount - shopifyCount
          );

        let status = "READY";

        if (sourceCount === 0) {
          status = "NO_SOURCE_IMAGES";
        } else if (shopifyCount === sourceCount) {
          status = "COMPLETE";
        } else if (shopifyCount > sourceCount) {
          status = "REVIEW_MORE_SHOPIFY_MEDIA";
        }

        results.push({
          name:
            sourceProduct.name ||
            item.productName,
          handle: item.handle,
          sourceImages: sourceCount,
          shopifyMedia: shopifyCount,
          missing,
          status
        });

        // Gentle pacing.
        await new Promise(
          (resolve) =>
            setTimeout(resolve, 150)
        );
      } catch (e) {
        results.push({
          name: item.productName,
          handle: item.handle,
          sourceImages: "",
          shopifyMedia: "",
          missing: "",
          status: `ERROR: ${String(e)}`
        });
      }
    }

    const totals = results.reduce(
      (acc, row) => {
        acc.products++;

        if (
          typeof row.sourceImages === "number"
        ) {
          acc.sourceImages +=
            row.sourceImages;
        }

        if (
          typeof row.shopifyMedia === "number"
        ) {
          acc.shopifyMedia +=
            row.shopifyMedia;
        }

        if (
          typeof row.missing === "number"
        ) {
          acc.missing +=
            row.missing;
        }

        if (row.status === "COMPLETE") {
          acc.complete++;
        }

        if (row.status === "READY") {
          acc.ready++;
        }

        if (
          !["READY", "COMPLETE"].includes(
            row.status
          )
        ) {
          acc.review++;
        }

        return acc;
      },
      {
        products: 0,
        sourceImages: 0,
        shopifyMedia: 0,
        missing: 0,
        complete: 0,
        ready: 0,
        review: 0
      }
    );

    const rows = results
      .map(
        (r) => `
          <tr>
            <td>${escapeHtml(r.name)}</td>
            <td><code>${escapeHtml(r.handle)}</code></td>
            <td>${escapeHtml(r.sourceImages)}</td>
            <td>${escapeHtml(r.shopifyMedia)}</td>
            <td>${escapeHtml(r.missing)}</td>
            <td>${escapeHtml(r.status)}</td>
          </tr>
        `
      )
      .join("");

    return res.send(
      page(
        "Gallery dry run — all products",
        `
          <h1>Gallery dry run — all products</h1>

          <div class="card">
            <p><strong>Products checked:</strong> ${totals.products}</p>
            <p><strong>Source images:</strong> ${totals.sourceImages}</p>
            <p><strong>Current Shopify media:</strong> ${totals.shopifyMedia}</p>
            <p><strong>Apparently missing:</strong> ${totals.missing}</p>
            <p><strong>Already complete:</strong> ${totals.complete}</p>
            <p><strong>Ready for migration:</strong> ${totals.ready}</p>
            <p><strong>Need review:</strong> ${totals.review}</p>
            <p><strong>Nothing was changed.</strong></p>
          </div>

          <div class="card">
            <table>
              <thead>
                <tr>
                  <th>Product</th>
                  <th>Handle</th>
                  <th>Source</th>
                  <th>Shopify</th>
                  <th>Missing</th>
                  <th>Status</th>
                </tr>
              </thead>
              <tbody>
                ${rows}
              </tbody>
            </table>
          </div>
        `
      )
    );
  } catch (e) {
    return res
      .status(500)
      .send(
        page(
          "Gallery dry run failed",
          `
            <h1>Gallery dry run failed</h1>
            <div class="card">
              <pre>${escapeHtml(String(e))}</pre>
            </div>
          `
        )
      );
  }
});
app.get("/gallery-migrate-zero-batch", async (req, res) => {
  try {
    const shop = String(
      req.query.shop || ALLOWED_SHOP || ""
    ).toLowerCase();

    if (!validShop(shop) || !tokens.has(shop)) {
      return res
        .status(401)
        .send("Authorize Shopify first");
    }

    const GODADDY_BASE =
      "https://b54aa1d3-662e-49ee-b390-0d4ebb6dcdbe.mysimplestore.com";

    const start = Math.max(
      0,
      Number.parseInt(String(req.query.start || "0"), 10) || 0
    );

    const limit = 5;

    const productsByHandle = new Map();

    for (const item of manifest) {
      if (!productsByHandle.has(item.handle)) {
        productsByHandle.set(item.handle, {
          handle: item.handle,
          productName: item.productName
        });
      }
    }

    const products = [...productsByHandle.values()];

    const eligible = [];
    const scanResults = [];

    for (const item of products) {
      try {
        const shopifyProduct =
          await getProduct(shop, item.handle);

        if (!shopifyProduct) {
          scanResults.push({
            name: item.productName,
            handle: item.handle,
            status: "NOT_FOUND_IN_SHOPIFY"
          });
          continue;
        }

        const validMedia =
          (shopifyProduct.media?.nodes || [])
            .filter(
              (media) =>
                media.status !== "FAILED"
            );

        if (validMedia.length !== 0) {
          continue;
        }

        const sourceUrl =
          `${GODADDY_BASE}/api/v2/products/` +
          `${encodeURIComponent(item.handle)}?app=vnext`;

        const sourceResponse =
          await fetch(sourceUrl, {
            headers: {
              "User-Agent":
                "Mozilla/5.0 CHB-Image-Migration/1.0",
              "Accept": "application/json"
            }
          });

        if (!sourceResponse.ok) {
          scanResults.push({
            name: item.productName,
            handle: item.handle,
            status:
              `SOURCE_API_${sourceResponse.status}`
          });
          continue;
        }

        const sourceProduct =
          await sourceResponse.json();

        const sourceImages =
          (sourceProduct.assets || [])
            .filter(
              (asset) =>
                asset &&
                asset.type === "image" &&
                asset.original_url
            )
            .map((asset, index) => ({
              position: index + 1,
              sourceUrl: String(
                asset.original_url
              ).split("/:/rs=")[0],
              productName:
                sourceProduct.name ||
                item.productName,
              handle: item.handle
            }));

        if (!sourceImages.length) {
          scanResults.push({
            name:
              sourceProduct.name ||
              item.productName,
            handle: item.handle,
            status: "NO_SOURCE_IMAGES"
          });
          continue;
        }

        eligible.push({
          name:
            sourceProduct.name ||
            item.productName,
          handle: item.handle,
          shopifyProduct,
          sourceImages
        });

        await new Promise(
          (resolve) =>
            setTimeout(resolve, 100)
        );
      } catch (e) {
        scanResults.push({
          name: item.productName,
          handle: item.handle,
          status: `SCAN_ERROR: ${String(e)}`
        });
      }
    }

    const batch =
      eligible.slice(start, start + limit);

    const results = [];

    for (const product of batch) {
      let added = 0;
      let error = "";

      for (const image of product.sourceImages) {
        try {
          console.log(
            `Zero-media migration: ${product.name} ` +
            `image ${image.position}/${product.sourceImages.length}`
          );

          await addImage(
            shop,
            product.shopifyProduct,
            image
          );

          added++;

          await new Promise(
            (resolve) =>
              setTimeout(resolve, 500)
          );
        } catch (e) {
          error = String(e);
          break;
        }
      }

      results.push({
        name: product.name,
        handle: product.handle,
        sourceImages:
          product.sourceImages.length,
        added,
        status:
          error
            ? "ERROR"
            : "SUBMITTED",
        error
      });
    }

    const nextStart =
      start + batch.length;

    const hasMore =
      nextStart < eligible.length;

    const rows = results
      .map(
        (r) => `
          <tr>
            <td>${escapeHtml(r.name)}</td>
            <td><code>${escapeHtml(r.handle)}</code></td>
            <td>${r.sourceImages}</td>
            <td>${r.added}</td>
            <td>${escapeHtml(r.status)}</td>
            <td>${escapeHtml(r.error || "")}</td>
          </tr>
        `
      )
      .join("");

    const nextLink = hasMore
      ? `
        <a
          class="button"
          href="/gallery-migrate-zero-batch?shop=${encodeURIComponent(shop)}&start=${nextStart}"
        >
          Run next batch
        </a>
      `
      : `
        <p><strong>No more zero-media products remain in this run.</strong></p>
      `;

    return res.send(
      page(
        "Zero-media gallery migration",
        `
          <h1>Zero-media gallery migration</h1>

          <div class="card">
            <p>
              <strong>Eligible zero-media products:</strong>
              ${eligible.length}
            </p>

            <p>
              <strong>Batch start:</strong>
              ${start}
            </p>

            <p>
              <strong>Products processed now:</strong>
              ${batch.length}
            </p>

            <p>
              Products that already had valid Shopify media were not touched.
            </p>
          </div>

          <div class="card">
            <table>
              <thead>
                <tr>
                  <th>Product</th>
                  <th>Handle</th>
                  <th>Source images</th>
                  <th>Submitted</th>
                  <th>Status</th>
                  <th>Error</th>
                </tr>
              </thead>
              <tbody>
                ${rows}
              </tbody>
            </table>
          </div>

          ${nextLink}
        `
      )
    );
  } catch (e) {
    return res
      .status(500)
      .send(
        page(
          "Batch migration stopped",
          `
            <h1>Batch migration stopped</h1>
            <div class="card">
              <pre>${escapeHtml(String(e))}</pre>
            </div>
          `
        )
      );
  }
});
app.get("/gallery-partial-dry-run", async (req, res) => {
  try {
    const shop = String(
      req.query.shop || ALLOWED_SHOP || ""
    ).toLowerCase();

    if (!validShop(shop) || !tokens.has(shop)) {
      return res
        .status(401)
        .send("Authorize Shopify first");
    }

    const GODADDY_BASE =
      "https://b54aa1d3-662e-49ee-b390-0d4ebb6dcdbe.mysimplestore.com";

    const targets = [
      {
        name: "Marine Set",
        handle: "marine-set"
      },
      {
        name: "Skyfall Set",
        handle: "skyfall-set"
      },
      {
        name: "Rosa Neon Delta Set",
        handle: "rosa-neon-delta-set"
      },
      {
        name: "PRE-ORDER Oceanos Set",
        handle: "pre-order-oceanos-set"
      },
      {
        name: "BERRY",
        handle: "lover-berry-set"
      },
      {
        name: "Mocha Set",
        handle: "mocha-set"
      },
      {
        name: "Pre-Order Divine Grace Hand Chain",
        handle: "pre-order-divine-grace-hand-chain"
      },
      {
        name: "Casa Lunar Set",
        handle: "casa-lunar-set"
      }
    ];

    const results = [];

    for (const target of targets) {
      try {
        const sourceUrl =
          `${GODADDY_BASE}/api/v2/products/` +
          `${encodeURIComponent(target.handle)}?app=vnext`;

        const sourceResponse = await fetch(sourceUrl, {
          headers: {
            "User-Agent":
              "Mozilla/5.0 CHB-Image-Migration/1.0",
            "Accept": "application/json"
          }
        });

        if (!sourceResponse.ok) {
          results.push({
            name: target.name,
            handle: target.handle,
            sourceCount: "",
            shopifyCount: "",
            missingCount: "",
            missingFiles: [],
            status:
              `SOURCE_API_${sourceResponse.status}`
          });

          continue;
        }

        const sourceProduct =
          await sourceResponse.json();

        const sourceImages =
          (sourceProduct.assets || [])
            .filter(
              (asset) =>
                asset &&
                asset.type === "image" &&
                asset.original_url
            )
            .map((asset, index) => {
              const cleanUrl =
                String(asset.original_url)
                  .split("/:/rs=")[0];

             return {
  position: index + 1,
  url: cleanUrl,
  width: Number(asset.attachment_width || 0),
  height: Number(asset.attachment_height || 0),
  filename:
    filenameFromUrl(
      cleanUrl,
      `image-${index + 1}`
    )
      .toLowerCase()
};
            });

        const shopifyData = await gql(
          shop,
          `
            query PartialGalleryProduct($handle: String!) {
              productByHandle(handle: $handle) {
                id
                title
                handle
                media(first: 50) {
                  nodes {
                    id
                    status
                    mediaContentType
                    ... on MediaImage {
                      image {
                        url
                        altText
                        width
                        height
                      }
                    }
                  }
                }
              }
            }
          `,
          {
            handle: target.handle
          }
        );

        const product =
          shopifyData.productByHandle;

        if (!product) {
          results.push({
            name: target.name,
            handle: target.handle,
            sourceCount:
              sourceImages.length,
            shopifyCount: "",
            missingCount: "",
            missingFiles: [],
            status: "NOT_FOUND_IN_SHOPIFY"
          });

          continue;
        }

        const shopifyImages =
  (product.media?.nodes || [])
    .filter(
      (media) =>
        media.status !== "FAILED" &&
        media.mediaContentType === "IMAGE" &&
        media.image?.url
    )
    .map((media) => ({
      url: media.image.url,
      width: Number(media.image.width || 0),
      height: Number(media.image.height || 0)
    }));

const dimensionCounts = new Map();

for (const image of shopifyImages) {
  const key =
    `${image.width}x${image.height}`;

  dimensionCounts.set(
    key,
    (dimensionCounts.get(key) || 0) + 1
  );
}

const missingImages = [];

for (const image of sourceImages) {
  const key =
    `${image.width}x${image.height}`;

  const remaining =
    dimensionCounts.get(key) || 0;

  if (remaining > 0) {
    dimensionCounts.set(
      key,
      remaining - 1
    );
  } else {
    missingImages.push(image);
  }
}

        results.push({
          name:
            sourceProduct.name ||
            target.name,
          handle: target.handle,
          sourceCount:
            sourceImages.length,
          shopifyCount:
            shopifyImages.length,
          missingCount:
            missingImages.length,
          missingFiles:
            missingImages.map(
              (image) =>
                `${image.position}. ${image.filename}`
            ),
          status:
            missingImages.length === 0
              ? "COMPLETE"
              : "READY"
        });

        await new Promise(
          (resolve) =>
            setTimeout(resolve, 150)
        );
      } catch (e) {
        results.push({
          name: target.name,
          handle: target.handle,
          sourceCount: "",
          shopifyCount: "",
          missingCount: "",
          missingFiles: [],
          status:
            `ERROR: ${String(e)}`
        });
      }
    }

    const totals = results.reduce(
      (acc, row) => {
        acc.products++;

        if (
          typeof row.sourceCount === "number"
        ) {
          acc.source += row.sourceCount;
        }

        if (
          typeof row.shopifyCount === "number"
        ) {
          acc.shopify += row.shopifyCount;
        }

        if (
          typeof row.missingCount === "number"
        ) {
          acc.missing += row.missingCount;
        }

        return acc;
      },
      {
        products: 0,
        source: 0,
        shopify: 0,
        missing: 0
      }
    );

    const rows = results
      .map(
        (r) => `
          <tr>
            <td>${escapeHtml(r.name)}</td>
            <td>
              <code>${escapeHtml(r.handle)}</code>
            </td>
            <td>${escapeHtml(r.sourceCount)}</td>
            <td>${escapeHtml(r.shopifyCount)}</td>
            <td>${escapeHtml(r.missingCount)}</td>
            <td>${escapeHtml(r.status)}</td>
            <td>
              ${escapeHtml(
                (r.missingFiles || []).join(", ")
              )}
            </td>
          </tr>
        `
      )
      .join("");

    return res.send(
      page(
        "Partial gallery dry run",
        `
          <h1>Partial gallery dry run</h1>

          <div class="card">
            <p>
              <strong>Products checked:</strong>
              ${totals.products}
            </p>

            <p>
              <strong>Source images:</strong>
              ${totals.source}
            </p>

            <p>
              <strong>Current Shopify images:</strong>
              ${totals.shopify}
            </p>

            <p>
              <strong>Images identified as missing:</strong>
              ${totals.missing}
            </p>

            <p>
              <strong>Nothing was changed.</strong>
            </p>
          </div>

          <div class="card">
            <table>
              <thead>
                <tr>
                  <th>Product</th>
                  <th>Handle</th>
                  <th>Source</th>
                  <th>Shopify</th>
                  <th>Missing</th>
                  <th>Status</th>
                  <th>Missing files</th>
                </tr>
              </thead>

              <tbody>
                ${rows}
              </tbody>
            </table>
          </div>
        `
      )
    );
  } catch (e) {
    return res
      .status(500)
      .send(
        page(
          "Partial gallery dry run failed",
          `
            <h1>Partial gallery dry run failed</h1>

            <div class="card">
              <pre>${escapeHtml(String(e))}</pre>
            </div>
          `
        )
      );
  }
});            
app.get("/marine-diagnostic", async (req, res) => {
  try {
    const shop = String(
      req.query.shop || ALLOWED_SHOP || ""
    ).toLowerCase();

    if (!validShop(shop) || !tokens.has(shop)) {
      return res
        .status(401)
        .send("Authorize Shopify first");
    }

    const allowedHandles = new Set([
  "marine-set",
  "skyfall-set",
  "rosa-neon-delta-set",
  "pre-order-divine-grace-hand-chain",
  "casa-lunar-set",
  "lover-berry-set"
]);

const handle = String(
  req.query.handle || "marine-set"
).toLowerCase();

if (!allowedHandles.has(handle)) {
  return res
    .status(400)
    .send("Product handle not allowed");
}

    const godaddyUrl =
      "https://b54aa1d3-662e-49ee-b390-0d4ebb6dcdbe.mysimplestore.com" +
      "/api/v2/products/" +
      encodeURIComponent(handle) +
      "?app=vnext";

    const sourceResponse = await fetch(godaddyUrl, {
      headers: {
        "User-Agent":
          "Mozilla/5.0 CHB-Image-Migration/1.0",
        "Accept": "application/json"
      }
    });

    if (!sourceResponse.ok) {
      throw new Error(
        `GoDaddy product API failed: ${sourceResponse.status}`
      );
    }

    const sourceProduct =
      await sourceResponse.json();

    const sourceImages =
      (sourceProduct.assets || [])
        .filter(
          (asset) =>
            asset &&
            asset.type === "image"
        )
        .map((asset, index) => ({
          position: index + 1,
          width:
            Number(asset.attachment_width || 0),
          height:
            Number(asset.attachment_height || 0),
          originalUrl:
            asset.original_url || "",
          productUrl:
            asset.product_url || "",
          smallUrl:
            asset.small_url || "",
          largeUrl:
            asset.large_url || "",
          zoomUrl:
            asset.zoom_image_url || ""
        }));

    const shopifyData = await gql(
      shop,
      `
        query MarineDiagnostic($handle: String!) {
          productByHandle(handle: $handle) {
            id
            title
            handle
            media(first: 20) {
              nodes {
                id
                status
                mediaContentType
                ... on MediaImage {
                  image {
                    url
                    altText
                    width
                    height
                  }
                }
              }
            }
          }
        }
      `,
      {
        handle
      }
    );

    const product =
      shopifyData.productByHandle;

    if (!product) {
      throw new Error(
        "Marine Set not found in Shopify"
      );
    }

    const shopifyImages =
      (product.media?.nodes || [])
        .filter(
          (media) =>
            media.status !== "FAILED" &&
            media.mediaContentType === "IMAGE" &&
            media.image?.url
        )
        .map((media, index) => ({
          position: index + 1,
          url: media.image.url,
          altText: media.image.altText || "",
          width: Number(media.image.width || 0),
          height: Number(media.image.height || 0)
        }));

    const sourceRows = sourceImages
      .map(
        (image) => `
          <tr>
            <td>${image.position}</td>
            <td>${image.width} x ${image.height}</td>
            <td>
              <code>${escapeHtml(image.originalUrl)}</code>
            </td>
            <td>
              <a href="${escapeHtml(image.productUrl)}" target="_blank">
                Product URL
              </a>
            </td>
            <td>
              <a href="${escapeHtml(image.smallUrl)}" target="_blank">
                Small URL
              </a>
            </td>
          </tr>
        `
      )
      .join("");

    const shopifyRows = shopifyImages
      .map(
        (image) => `
          <tr>
            <td>${image.position}</td>
            <td>${image.width} x ${image.height}</td>
            <td>${escapeHtml(image.altText)}</td>
            <td>
              <a href="${escapeHtml(image.url)}" target="_blank">
                Open Shopify image
              </a>
            </td>
          </tr>
        `
      )
      .join("");

    return res.send(
      page(
        "Marine Set diagnostic",
        `
          <h1>Marine Set diagnostic</h1>

          <div class="card">
            <p>
              <strong>Source images:</strong>
              ${sourceImages.length}
            </p>

            <p>
              <strong>Shopify images:</strong>
              ${shopifyImages.length}
            </p>

            <p>
              <strong>Nothing was changed.</strong>
            </p>
          </div>

          <div class="card">
            <h2>GoDaddy source images</h2>

            <table>
              <thead>
                <tr>
                  <th>Position</th>
                  <th>Original dimensions</th>
                  <th>Original URL</th>
                  <th>Product URL</th>
                  <th>Small URL</th>
                </tr>
              </thead>
              <tbody>
                ${sourceRows}
              </tbody>
            </table>
          </div>

          <div class="card">
            <h2>Current Shopify images</h2>

            <table>
              <thead>
                <tr>
                  <th>Position</th>
                  <th>Dimensions</th>
                  <th>Alt text</th>
                  <th>Shopify URL</th>
                </tr>
              </thead>
              <tbody>
                ${shopifyRows}
              </tbody>
            </table>
          </div>
        `
      )
    );
  } catch (e) {
    return res
      .status(500)
      .send(
        page(
          "Marine diagnostic failed",
          `
            <h1>Marine diagnostic failed</h1>
            <div class="card">
              <pre>${escapeHtml(String(e))}</pre>
            </div>
          `
        )
      );
  }
});
app.get("/migrate-final-28", async (req, res) => {
  try {
    const shop = String(
      req.query.shop || ALLOWED_SHOP || ""
    ).toLowerCase();

    if (!validShop(shop) || !tokens.has(shop)) {
      return res
        .status(401)
        .send("Authorize Shopify first");
    }

    const GODADDY_BASE =
      "https://b54aa1d3-662e-49ee-b390-0d4ebb6dcdbe.mysimplestore.com";

    const targets = [
      {
        name: "Marine Set",
        handle: "marine-set",
        expectedSource: 6
      },
      {
        name: "Skyfall Set",
        handle: "skyfall-set",
        expectedSource: 5
      },
      {
        name: "Rosa Neon Delta Set",
        handle: "rosa-neon-delta-set",
        expectedSource: 7
      },
      {
        name: "Pre-Order Divine Grace Hand Chain",
        handle: "pre-order-divine-grace-hand-chain",
        expectedSource: 3
      },
      {
        name: "Casa Lunar Set",
        handle: "casa-lunar-set",
        expectedSource: 12
      }
    ];

    const prepared = [];

    // PRE-FLIGHT: verify everything before changing anything.
    for (const target of targets) {
      const sourceUrl =
        `${GODADDY_BASE}/api/v2/products/` +
        `${encodeURIComponent(target.handle)}?app=vnext`;

      const sourceResponse = await fetch(sourceUrl, {
        headers: {
          "User-Agent":
            "Mozilla/5.0 CHB-Image-Migration/1.0",
          "Accept": "application/json"
        }
      });

      if (!sourceResponse.ok) {
        throw new Error(
          `${target.name}: source API returned ${sourceResponse.status}`
        );
      }

      const sourceProduct =
        await sourceResponse.json();

      const sourceImages =
        (sourceProduct.assets || [])
          .filter(
            (asset) =>
              asset &&
              asset.type === "image" &&
              asset.original_url
          )
          .map((asset, index) => ({
            position: index + 1,
            sourceUrl: String(
              asset.original_url
            ).split("/:/rs=")[0],
            productName:
              sourceProduct.name ||
              target.name,
            handle: target.handle
          }));

      if (
        sourceImages.length !==
        target.expectedSource
      ) {
        throw new Error(
          `${target.name}: safety stop — expected ` +
          `${target.expectedSource} source images, found ` +
          `${sourceImages.length}`
        );
      }

      const shopifyProduct =
        await getProduct(
          shop,
          target.handle
        );

      if (!shopifyProduct) {
        throw new Error(
          `${target.name}: product not found in Shopify`
        );
      }

      const validMedia =
        (shopifyProduct.media?.nodes || [])
          .filter(
            (media) =>
              media.status !== "FAILED"
          );

      if (validMedia.length !== 1) {
        throw new Error(
          `${target.name}: safety stop — expected ` +
          `1 current Shopify image, found ` +
          `${validMedia.length}`
        );
      }

      prepared.push({
        ...target,
        shopifyProduct,
        imagesToAdd:
          sourceImages.slice(1)
      });
    }

    const expectedToAdd =
      prepared.reduce(
        (sum, product) =>
          sum + product.imagesToAdd.length,
        0
      );

    if (expectedToAdd !== 28) {
      throw new Error(
        `Global safety stop — expected 28 images ` +
        `to add, calculated ${expectedToAdd}`
      );
    }

    const results = [];
    let totalSubmitted = 0;
    let stopped = false;

    for (const product of prepared) {
      let submitted = 0;
      let error = "";

      for (const image of product.imagesToAdd) {
        try {
          console.log(
            `Final 28 migration: ${product.name} ` +
            `image ${image.position}/${product.expectedSource}`
          );

          await addImage(
            shop,
            product.shopifyProduct,
            image
          );

          submitted++;
          totalSubmitted++;

          await new Promise(
            (resolve) =>
              setTimeout(resolve, 600)
          );
        } catch (e) {
          error = String(e);
          stopped = true;
          break;
        }
      }

      results.push({
        name: product.name,
        expected:
          product.imagesToAdd.length,
        submitted,
        status:
          error
            ? "ERROR"
            : "SUBMITTED",
        error
      });

      if (stopped) {
        break;
      }
    }

    const rows = results
      .map(
        (r) => `
          <tr>
            <td>${escapeHtml(r.name)}</td>
            <td>${r.expected}</td>
            <td>${r.submitted}</td>
            <td>${escapeHtml(r.status)}</td>
            <td>${escapeHtml(r.error || "")}</td>
          </tr>
        `
      )
      .join("");

    return res.send(
      page(
        "Final 28 gallery migration",
        `
          <h1>Final 28 gallery migration</h1>

          <div class="card">
            <p>
              <strong>Products:</strong> 5
            </p>

            <p>
              <strong>Expected images:</strong> 28
            </p>

            <p>
              <strong>Submitted:</strong>
              ${totalSubmitted}
            </p>

            <p>
              <strong>Stopped on error:</strong>
              ${stopped ? "YES" : "NO"}
            </p>
          </div>

          <div class="card">
            <table>
              <thead>
                <tr>
                  <th>Product</th>
                  <th>Expected</th>
                  <th>Submitted</th>
                  <th>Status</th>
                  <th>Error</th>
                </tr>
              </thead>
              <tbody>
                ${rows}
              </tbody>
            </table>
          </div>
        `
      )
    );
  } catch (e) {
    return res
      .status(500)
      .send(
        page(
          "Final migration stopped",
          `
            <h1>Final migration stopped</h1>

            <div class="card">
              <pre>${escapeHtml(String(e))}</pre>
            </div>
          `
        )
      );
  }
});
app.listen(PORT, "0.0.0.0", () => {
  console.log(`CHB Image Migration listening on port ${PORT}`);
});

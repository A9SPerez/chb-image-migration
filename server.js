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

    const matches = [
      ...html.matchAll(
        /https?:\/\/[a-zA-Z0-9.-]+\.mysimplestore\.com/g
      )
    ].map((m) => m[0]);

    const hosts = [...new Set(matches)];

    const report = {
      websiteStatus: siteResponse.status,
      htmlLength: html.length,
      mySimpleStoreHosts: hosts,
      apiTests: []
    };

    for (const base of hosts) {
      const apiUrl =
        `${base}/api/v2/products` +
        `?page_fallback=true&app=vnext&page=1&per_page=100`;

      try {
        const apiResponse = await fetch(apiUrl, {
          headers: {
            "User-Agent": "Mozilla/5.0 CHB-Image-Migration/1.0",
            "Accept": "application/json,*/*"
          }
        });

        const body = await apiResponse.text();

        report.apiTests.push({
          base,
          status: apiResponse.status,
          contentType:
            apiResponse.headers.get("content-type"),
          preview: body.slice(0, 15000)
        });
      } catch (e) {
        report.apiTests.push({
          base,
          error: String(e)
        });
      }
    }

    res
      .type("text/plain")
      .send(JSON.stringify(report, null, 2));
  } catch (e) {
    res.status(500).type("text/plain").send(String(e));
  }
});
app.listen(PORT, "0.0.0.0", () => {
  console.log(`CHB Image Migration listening on port ${PORT}`);
});

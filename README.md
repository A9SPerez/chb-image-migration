# CHB Image Migration

One-time Shopify media migration tool for Call Her Bronzeada.

## Safety design

- Reads products by handle.
- Adds product media only.
- Does not change variants, prices, inventory, status, or collections.
- Skips products that already have Shopify media.
- Tokens are stored only in server memory and are lost on restart.

## Manifest

This bundle contains 84 product/image associations generated from the GoDaddy export.

## Render environment variables

Set these in Render (never commit secrets to GitHub):

- `SHOPIFY_CLIENT_ID`
- `SHOPIFY_CLIENT_SECRET`
- `APP_URL` — your Render URL, for example `https://chb-image-migration.onrender.com`
- `ALLOWED_SHOP` — `ppa31z-gj.myshopify.com`
- `SHOPIFY_API_VERSION` — `2026-07`
- `SHOPIFY_SCOPES` — `read_products,write_products`

## Shopify app version

After Render gives you the public URL, create a new Shopify app version with:

- App URL: your Render URL
- Allowed redirect URL: `YOUR_RENDER_URL/auth/callback`
- Scopes: `read_products,write_products`

Then release the new version.

## Migration sequence

1. Open the app with the store query parameter.
2. Authorize Shopify.
3. Run **Dry run**.
4. Test **Finale Verde Set**.
5. Verify the product in Shopify.
6. Run **Migrate missing images** only after verification.

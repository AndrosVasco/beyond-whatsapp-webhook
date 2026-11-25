const JSON_HEADERS = {
  "content-type": "application/json; charset=UTF-8",
  "cache-control": "no-store"
};

export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    // Ruta para comprobar que el Worker está funcionando.
    if (url.pathname === "/health") {
      return jsonResponse({
        ok: true,
        service: "beyond-whatsapp-webhook",
        timestamp: new Date().toISOString()
      });
    }

    if (url.pathname !== "/meta-webhook") {
      return jsonResponse(
        {
          ok: false,
          error: "NOT_FOUND"
        },
        404
      );
    }

    // Verificación inicial del webhook realizada por Meta.
    if (request.method === "GET") {
      return verifyWebhook(url, env);
    }

    if (request.method !== "POST") {
      return jsonResponse(
        {
          ok: false,
          error: "METHOD_NOT_ALLOWED"
        },
        405,
        {
          Allow: "GET, POST"
        }
      );
    }

    if (!env.META_APP_SECRET || !env.N8N_WEBHOOK_URL) {
      console.error(
        JSON.stringify({
          event: "missing_configuration"
        })
      );

      return jsonResponse(
        {
          ok: false,
          error: "SERVICE_NOT_CONFIGURED"
        },
        500
      );
    }

    const rawBody = await request.text();
    const signature = request.headers.get("x-hub-signature-256");

    const validSignature = await verifyMetaSignature(
      rawBody,
      signature,
      env.META_APP_SECRET
    );

    if (!validSignature) {
      console.warn(
        JSON.stringify({
          event: "invalid_meta_signature"
        })
      );

      return jsonResponse(
        {
          ok: false,
          error: "INVALID_SIGNATURE"
        },
        401
      );
    }

    let payload;

    try {
      payload = JSON.parse(rawBody);
    } catch {
      return jsonResponse(
        {
          ok: false,
          error: "INVALID_JSON"
        },
        400
      );
    }

    // Meta puede enviar eventos de otros productos.
    if (payload?.object !== "whatsapp_business_account") {
      return jsonResponse({
        ok: true,
        forwarded: false,
        reason: "UNSUPPORTED_OBJECT"
      });
    }

    const relevantValues = getRelevantValues(
      payload,
      env.META_PHONE_NUMBER_ID
    );

    const messageCount = relevantValues.reduce(
      (total, value) =>
        total + (Array.isArray(value.messages) ? value.messages.length : 0),
      0
    );

    const statuses = relevantValues.flatMap((value) =>
      Array.isArray(value.statuses) ? value.statuses : []
    );

    const failedStatuses = statuses.filter(
      (status) => status?.status === "failed"
    );

    // Solo registramos información técnica, nunca textos ni teléfonos.
    if (failedStatuses.length > 0) {
      console.warn(
        JSON.stringify({
          event: "whatsapp_failed_status",
          count: failedStatuses.length,
          messageIds: failedStatuses
            .map((status) => status.id)
            .filter(Boolean)
        })
      );
    }

    // Los estados sent, delivered y read terminan aquí.
    if (messageCount === 0) {
      console.log(
        JSON.stringify({
          event: "whatsapp_event_filtered",
          statuses: statuses.length
        })
      );

      return jsonResponse({
        ok: true,
        forwarded: false,
        messages: 0,
        statusesFiltered: statuses.length
      });
    }

    // Conserva únicamente cambios que tengan mensajes.
    const messagePayload = buildMessagePayload(
      payload,
      env.META_PHONE_NUMBER_ID
    );

    const forwardHeaders = new Headers({
      "content-type": "application/json",
      "x-meta-signature-verified": "true",
      "x-cloudflare-worker": "beyond-whatsapp-webhook"
    });

    if (env.N8N_PROXY_SECRET) {
      forwardHeaders.set("x-proxy-secret", env.N8N_PROXY_SECRET);
    }

    let n8nResponse;

    try {
      n8nResponse = await fetch(env.N8N_WEBHOOK_URL, {
        method: "POST",
        headers: forwardHeaders,
        body: JSON.stringify(messagePayload)
      });
    } catch (error) {
      console.error(
        JSON.stringify({
          event: "n8n_connection_error",
          error: String(error)
        })
      );

      // El error permite que Meta reintente posteriormente.
      return jsonResponse(
        {
          ok: false,
          error: "N8N_CONNECTION_ERROR"
        },
        502
      );
    }

    if (!n8nResponse.ok) {
      console.error(
        JSON.stringify({
          event: "n8n_response_error",
          status: n8nResponse.status
        })
      );

      return jsonResponse(
        {
          ok: false,
          error: "N8N_REJECTED_EVENT"
        },
        502
      );
    }

    console.log(
      JSON.stringify({
        event: "messages_forwarded",
        messages: messageCount,
        statusesFiltered: statuses.length
      })
    );

    return jsonResponse({
      ok: true,
      forwarded: true,
      messages: messageCount,
      statusesFiltered: statuses.length
    });
  }
};

function verifyWebhook(url, env) {
  const mode = url.searchParams.get("hub.mode");
  const token = url.searchParams.get("hub.verify_token");
  const challenge = url.searchParams.get("hub.challenge");

  const valid =
    mode === "subscribe" &&
    Boolean(env.META_VERIFY_TOKEN) &&
    constantTimeEqual(token || "", env.META_VERIFY_TOKEN);

  if (!valid) {
    return new Response("Invalid verification token", {
      status: 403
    });
  }

  return new Response(challenge || "", {
    status: 200,
    headers: {
      "content-type": "text/plain; charset=UTF-8",
      "cache-control": "no-store"
    }
  });
}

function getRelevantValues(payload, phoneNumberId) {
  const values = [];

  for (const entry of payload?.entry || []) {
    for (const change of entry?.changes || []) {
      const value = change?.value;

      if (!value) {
        continue;
      }

      const eventPhoneNumberId = value?.metadata?.phone_number_id;

      if (
        phoneNumberId &&
        eventPhoneNumberId &&
        eventPhoneNumberId !== phoneNumberId
      ) {
        continue;
      }

      values.push(value);
    }
  }

  return values;
}

function buildMessagePayload(payload, phoneNumberId) {
  const entries = [];

  for (const entry of payload?.entry || []) {
    const changes = [];

    for (const change of entry?.changes || []) {
      const value = change?.value;
      const messages = Array.isArray(value?.messages)
        ? value.messages
        : [];

      if (messages.length === 0) {
        continue;
      }

      const eventPhoneNumberId = value?.metadata?.phone_number_id;

      if (
        phoneNumberId &&
        eventPhoneNumberId &&
        eventPhoneNumberId !== phoneNumberId
      ) {
        continue;
      }

      const cleanValue = {
        ...value,
        messages
      };

      // No se envían estados a n8n, incluso si llegaron junto a un mensaje.
      delete cleanValue.statuses;

      changes.push({
        ...change,
        value: cleanValue
      });
    }

    if (changes.length > 0) {
      entries.push({
        ...entry,
        changes
      });
    }
  }

  return {
    ...payload,
    entry: entries
  };
}

async function verifyMetaSignature(rawBody, signatureHeader, appSecret) {
  if (
    !signatureHeader ||
    !signatureHeader.startsWith("sha256=") ||
    !appSecret
  ) {
    return false;
  }

  const receivedSignature = signatureHeader
    .slice("sha256=".length)
    .toLowerCase();

  const encoder = new TextEncoder();

  const key = await crypto.subtle.importKey(
    "raw",
    encoder.encode(appSecret),
    {
      name: "HMAC",
      hash: "SHA-256"
    },
    false,
    ["sign"]
  );

  const digest = await crypto.subtle.sign(
    "HMAC",
    key,
    encoder.encode(rawBody)
  );

  const expectedSignature = Array.from(new Uint8Array(digest))
    .map((byte) => byte.toString(16).padStart(2, "0"))
    .join("");

  return constantTimeEqual(receivedSignature, expectedSignature);
}

function constantTimeEqual(first, second) {
  if (first.length !== second.length) {
    return false;
  }

  let difference = 0;

  for (let index = 0; index < first.length; index += 1) {
    difference |= first.charCodeAt(index) ^ second.charCodeAt(index);
  }

  return difference === 0;
}

function jsonResponse(body, status = 200, extraHeaders = {}) {
  return new Response(JSON.stringify(body), {
    status,
    headers: {
      ...JSON_HEADERS,
      ...extraHeaders
    }
  });
}
import { app, HttpRequest, HttpResponseInit, InvocationContext } from "@azure/functions";
import * as crypto from "crypto";

const SECRET = process.env.CI_NOTIFY_SECRET || "";

function verifySignature(rawBody: string, signatureHeader?: string): boolean {
    if(!signatureHeader?.startsWith("sha256=")) return false;
    // signatureHeaderがsha256=で始まることを確認
    const sig = signatureHeader.slice("sha256=".length);
    // sha256=の部分を除去
    const expected = crypto.createHmac("sha256",SECRET).update(rawBody,"utf8").digest("hex");
    // SECRETを使ってHMAC-SHA256で署名を生成
    return crypto.timingSafeEqual(Buffer.from(sig), Buffer.from(expected));
    // 生成した署名とヘッダーの署名を比較
}

// Slackに通知を送る関数
async function postToSlack(p: any) {
    const url = process.env.SLACK_WEBHOOK_URL!;
    const emoji = p.status === "success" ? "✅" : (p.status === "canceled" ? "⚠️" : "❌");
    const text = `${emoji} *${p.workflow}* #${p.run_number} on \`${p.ref}\` by ${p.actor}\n${p.html_url}\ncommit: \`${p.sha.substring(0,7)}\``;
    await fetch(url, {
        method: "POST",
        headers: {
            "Content-Type": "application/json"
        },
        body: JSON.stringify({
            text
        })
    });
}

export async function NotifyCI(request: HttpRequest, context: InvocationContext): Promise<HttpResponseInit> {
    context.log(`Http function processed request for url "${request.url}"`);
    
    const rawBody = await request.text();
    // リクエストのボディを取得
    const ok = verifySignature(rawBody, request.headers.get("x-signature-256") || undefined);
    // ヘッダーから署名を取得し、検証
    if(!ok) {
        context.log("Signature verification failed");
        return {
            status: 401,
            jsonBody: {
                ok: false,
                reason: "invalid signature"
            }
        };
    }
    // 署名が無効な場合は401 Unauthorizedを返す

    const payload = JSON.parse(rawBody);
    // ボディをJSONとしてパース
    context.log("CI Notification received", payload);

    // Slackへの通知を試みる
    try {
        await postToSlack(payload);
        context.log("Notification sent to Slack");
    } catch (error) {
        context.log("Failed to send notification to Slack", error);
    }


    return {
        status: 200,
        jsonBody: {
            ok: true
        }
    }
    // 成功した場合は200 OKを返す
};

app.http('NotifyCI', {
    methods: ['POST'],
    authLevel: 'anonymous',
    handler: NotifyCI
});

import { NextResponse } from "next/server";
import { getApiKeys, createApiKey, KEY_TIER } from "@/lib/localDb";
import { getConsistentMachineId } from "@/shared/utils/machineId";
import { validateAllowedConnectionIds } from "@/lib/auth/allowedConnections";

export const dynamic = "force-dynamic";

// GET /api/keys - List API keys
export async function GET() {
  try {
    const keys = await getApiKeys();
    return NextResponse.json({ keys });
  } catch (error) {
    console.log("Error fetching keys:", error);
    return NextResponse.json({ error: "Failed to fetch keys" }, { status: 500 });
  }
}

// POST /api/keys - Create new API key
export async function POST(request) {
  try {
    const body = await request.json();
    const { name, tier, expiresAt, tokenLimit, allowedModels, allowedConnectionIds } = body;

    if (!name) {
      return NextResponse.json({ error: "Name is required" }, { status: 400 });
    }

    // Validate tier (defaults handled in repo)
    if (tier !== undefined && tier !== KEY_TIER.UNLIMITED && tier !== KEY_TIER.RESTRICTED) {
      return NextResponse.json({ error: `Invalid tier. Must be '${KEY_TIER.UNLIMITED}' or '${KEY_TIER.RESTRICTED}'` }, { status: 400 });
    }

    // Validate expiresAt if provided
    if (expiresAt && Number.isNaN(Date.parse(expiresAt))) {
      return NextResponse.json({ error: "Invalid expiresAt date" }, { status: 400 });
    }

    // Validate tokenLimit if provided
    if (tokenLimit != null && (typeof tokenLimit !== "number" || tokenLimit < 0 || !Number.isFinite(tokenLimit))) {
      return NextResponse.json({ error: "tokenLimit must be a non-negative number" }, { status: 400 });
    }

    // Validate allowedModels if provided
    if (allowedModels !== undefined && !Array.isArray(allowedModels)) {
      return NextResponse.json({ error: "allowedModels must be an array of model ids" }, { status: 400 });
    }

    // Validate allowedConnectionIds if provided
    const accountValidation = await validateAllowedConnectionIds(allowedConnectionIds);
    if (!accountValidation.ok) {
      return NextResponse.json({ error: accountValidation.error }, { status: 400 });
    }

    // Always get machineId from server
    const machineId = await getConsistentMachineId();
    const apiKey = await createApiKey(name, machineId, {
      tier,
      expiresAt: expiresAt || null,
      tokenLimit: tokenLimit ?? null,
      allowedModels: allowedModels || [],
      allowedConnectionIds: accountValidation.list,
    });

    return NextResponse.json({
      key: apiKey.key,
      name: apiKey.name,
      id: apiKey.id,
      machineId: apiKey.machineId,
      tier: apiKey.tier,
      expiresAt: apiKey.expiresAt,
      tokenLimit: apiKey.tokenLimit,
      tokenUsed: apiKey.tokenUsed,
      allowedModels: apiKey.allowedModels,
      allowedConnectionIds: apiKey.allowedConnectionIds,
      status: apiKey.status,
    }, { status: 201 });
  } catch (error) {
    console.log("Error creating key:", error);
    return NextResponse.json({ error: "Failed to create key" }, { status: 500 });
  }
}

import { NextResponse } from "next/server";
import { deleteApiKey, getApiKeyById, updateApiKey, KEY_TIER } from "@/lib/localDb";

// GET /api/keys/[id] - Get single key
export async function GET(request, { params }) {
  try {
    const { id } = await params;
    const key = await getApiKeyById(id);
    if (!key) {
      return NextResponse.json({ error: "Key not found" }, { status: 404 });
    }
    return NextResponse.json({ key });
  } catch (error) {
    console.log("Error fetching key:", error);
    return NextResponse.json({ error: "Failed to fetch key" }, { status: 500 });
  }
}

// PUT /api/keys/[id] - Update key
export async function PUT(request, { params }) {
  try {
    const { id } = await params;
    const body = await request.json();
    const { isActive, name, tier, expiresAt, tokenLimit, allowedModels } = body;

    const existing = await getApiKeyById(id);
    if (!existing) {
      return NextResponse.json({ error: "Key not found" }, { status: 404 });
    }

    // Validate tier
    if (tier !== undefined && tier !== KEY_TIER.UNLIMITED && tier !== KEY_TIER.RESTRICTED) {
      return NextResponse.json({ error: `Invalid tier. Must be '${KEY_TIER.UNLIMITED}' or '${KEY_TIER.RESTRICTED}'` }, { status: 400 });
    }

    // Validate expiresAt (null is allowed = clear)
    if (expiresAt !== undefined && expiresAt !== null && Number.isNaN(Date.parse(expiresAt))) {
      return NextResponse.json({ error: "Invalid expiresAt date" }, { status: 400 });
    }

    // Validate tokenLimit (null is allowed = clear)
    if (
      tokenLimit !== undefined && tokenLimit !== null &&
      (typeof tokenLimit !== "number" || tokenLimit < 0 || !Number.isFinite(tokenLimit))
    ) {
      return NextResponse.json({ error: "tokenLimit must be a non-negative number or null" }, { status: 400 });
    }

    // Validate allowedModels
    if (allowedModels !== undefined && !Array.isArray(allowedModels)) {
      return NextResponse.json({ error: "allowedModels must be an array of model ids" }, { status: 400 });
    }

    const updateData = {};
    if (isActive !== undefined) updateData.isActive = isActive;
    if (name !== undefined) updateData.name = name;
    if (tier !== undefined) updateData.tier = tier;
    if (expiresAt !== undefined) updateData.expiresAt = expiresAt;
    if (tokenLimit !== undefined) updateData.tokenLimit = tokenLimit;
    if (allowedModels !== undefined) updateData.allowedModels = allowedModels;

    const updated = await updateApiKey(id, updateData);

    return NextResponse.json({ key: updated });
  } catch (error) {
    console.log("Error updating key:", error);
    return NextResponse.json({ error: "Failed to update key" }, { status: 500 });
  }
}

// DELETE /api/keys/[id] - Delete API key
export async function DELETE(request, { params }) {
  try {
    const { id } = await params;

    const deleted = await deleteApiKey(id);
    if (!deleted) {
      return NextResponse.json({ error: "Key not found" }, { status: 404 });
    }

    return NextResponse.json({ message: "Key deleted successfully" });
  } catch (error) {
    console.log("Error deleting key:", error);
    return NextResponse.json({ error: "Failed to delete key" }, { status: 500 });
  }
}

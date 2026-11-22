<?php
/**
 * Demo library — simulates real-world layered input handling.
 * User input flows through helpers before reaching a security comparison.
 */

function normalizeInput($value) {
    // A harmless-looking cleanup layer; taint survives.
    return trim((string)$value);
}

function wrapForCompare($value) {
    // Second layer: lower-casing before comparison.
    return strtolower(normalizeInput($value));
}

function computeDigest(string $algo, $value) {
    // Wrapper around hash functions used by the token endpoint.
    return hash($algo, $value);
}

function loadKnownToken(): string {
    // Pretend this comes from a database row.
    return '0e123456789012345678901234567890';
}

function lookupRoleLabel($role) {
    // Another indirection layer for the layered demo.
    return wrapForCompare($role);
}

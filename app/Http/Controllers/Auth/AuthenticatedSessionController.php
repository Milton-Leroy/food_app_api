<?php

namespace App\Http\Controllers\Auth;

use App\Http\Controllers\Controller;
use App\Http\Requests\Auth\LoginRequest;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Http\Response;
use Illuminate\Support\Facades\Auth;
use Illuminate\Validation\ValidationException;

class AuthenticatedSessionController extends Controller
{
    /**
     * Handle an incoming authentication request.
     */
    public function store(LoginRequest $request): JsonResponse
    {
        try {
            // Authenticate the user
            $request->authenticate();

            // Get the authenticated user
            $user = $request->user();

            // Delete old tokens
            $user->tokens()->delete();

            // Create a new token
            $token = $user->createToken('api-token');

            return response()->json([
                'user' => $user,
                'token' => $token->plainTextToken,
            ]);
        } catch (ValidationException $e) {
            // Handle invalid credentials
            return response()->json([
                'message' => 'Invalid credentials',
                'errors' => $e->errors(),
            ], JsonResponse::HTTP_UNAUTHORIZED);
        }

    }

    /**
     * Destroy an authenticated session.
     */
    public function destroy(Request $request): Response
    {
        Auth::guard('web')->logout();

        $request->session()->invalidate();

        $request->session()->regenerateToken();

        return response()->noContent();
    }
}

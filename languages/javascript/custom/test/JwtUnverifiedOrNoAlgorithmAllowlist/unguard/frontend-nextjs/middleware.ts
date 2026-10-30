import { NextRequest, NextResponse } from 'next/server';
import { jwtDecode } from 'jwt-decode';

const protectedRoutes = ['/users', '/mytimeline', '/ad-manager'];

export function middleware(req: NextRequest) {
    const jwt = req.cookies.get('jwt')?.value;

    const isProtected = protectedRoutes.includes(req.nextUrl.pathname);

    if (!jwt && isProtected) {
        return NextResponse.redirect(new URL('/login', req.url));
    }

    if (jwt) {
        try {
            // BAD: only checks that the cookie decodes, never verifies the signature
            jwtDecode(jwt); // $ Alert
        } catch {
            req.cookies.delete('jwt');
            return NextResponse.redirect(new URL('/login', req.url));
        }
    }

    return NextResponse.next();
}

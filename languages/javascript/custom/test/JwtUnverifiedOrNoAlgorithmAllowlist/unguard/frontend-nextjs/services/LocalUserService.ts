import { cookies } from 'next/headers';
import { jwtDecode, JwtPayload } from 'jwt-decode';

export interface CustomPayLoad extends JwtPayload {
    username: string;
    userid: string;
    roles: string[];
}

export async function isOwnProfile(username: string): Promise<boolean> {
    const cookieStore = await cookies();

    if (cookieStore.has('jwt')) {
        const jwt = cookieStore.get('jwt')?.value;

        if (jwt) {
            // BAD: identity taken from an unverified cookie
            const decodedPayload = jwtDecode<CustomPayLoad>(jwt); // $ Alert

            if (decodedPayload.username == username) {
                return true;
            }
        }
    }

    return false;
}

export async function getUsernameFromJwt(): Promise<string | undefined> {
    const cookieStore = await cookies();
    const jwt = cookieStore.get('jwt')?.value;
    if (jwt) {
        // BAD: identity taken from an unverified cookie
        return jwtDecode<CustomPayLoad>(jwt).username; // $ Alert
    }
    return undefined;
}

export async function isAdManager(): Promise<boolean> {
    const jwt = (await cookies()).get('jwt')?.value;
    if (jwt) {
        // BAD: role taken from an unverified cookie
        return jwtDecode<CustomPayLoad>(jwt).roles.includes('AD_MANAGER'); // $ Alert
    }
    return false;
}

export async function getLocale(): Promise<string | undefined> {
    // GOOD: not a JWT decode
    return (await cookies()).get('locale')?.value;
}

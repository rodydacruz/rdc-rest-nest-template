import { Injectable } from '@nestjs/common';
import { ForbiddenException } from '@nestjs/common/exceptions';
import { PrismaClientKnownRequestError } from '@prisma/client/runtime';
import { PrismaService } from 'src/prisma/prisma.service';
import { AuthDto } from './dto';
import * as argon from 'argon2';
import { JwtService } from '@nestjs/jwt/dist';
import { ConfigService } from '@nestjs/config';

@Injectable({})
export class AuthService {
    constructor(
        private prisma: PrismaService,
        private jwt: JwtService,
        private config: ConfigService,
    ) { }

    /**
     *
     * @param dto
     * @returns
     */
    async signup(dto: AuthDto) {
        //Generate the password
        const hash = await argon.hash(dto.password);
        //save the new user
        try {
            const user = await this.prisma.user.create({
                data: {
                    email: dto.email,
                    hash,
                },
            });

            return this.signToken(user.id, user.email);

        } catch (error) {
            if (error instanceof PrismaClientKnownRequestError) {
                if (error.code === 'P2002') {
                    throw new ForbiddenException('Credentials Taken');
                }
            }
            throw error;
        }
    }
    /**
     *
     * @param dto
     */
    async signin(dto: AuthDto) {
        //fing the user
        const user = await this.prisma.user.findUnique({
            where: {
                email: dto.email,
            },
        });
        //If user does not exist trow exeption
        if (!user) throw new ForbiddenException('Credencials incorrecy');

        //comparee password
        const pwMatches = await argon.verify(user.hash, dto.password);
        if (!pwMatches) throw new ForbiddenException('Credencials incorrecy');

        return this.signToken(user.id, user.email);
    }

    async signToken(userId: number,
        email: string): Promise<{ jwt_token: string }> {
        const payload = {
            sub: userId,
            email
        }
        const secret = this.config.get('JWT_SECRET');

        const token = await this.jwt.signAsync(payload, {
            expiresIn: "30m",
            secret: secret,
        });

        return {
            jwt_token: token,
        }
    }
}

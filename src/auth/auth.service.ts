import { Injectable } from '@nestjs/common';
import { ForbiddenException } from '@nestjs/common/exceptions';
import { PrismaClientKnownRequestError } from '@prisma/client/runtime';
import { PrismaService } from 'src/prisma/prisma.service';
import { AuthDto } from './dto';
import * as argon from 'argon2';

@Injectable({})
export class AuthService {
  constructor(private prisma: PrismaService) {}

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

      delete user.hash;
      // return the saved user
      return user;
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

    delete user.hash;
    //sendbacl the user
    return user;
  }
}

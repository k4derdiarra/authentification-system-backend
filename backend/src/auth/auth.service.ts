import { ForbiddenException, Injectable } from '@nestjs/common';
import { AuthDto } from './dto';
import * as bcrypt from 'bcrypt';
import { PrismaService } from '../prisma/prisma.service';
import { PrismaClientKnownRequestError } from '@prisma/client/runtime';
import { JwtService } from '@nestjs/jwt';
import { ConfigService } from '@nestjs/config';

@Injectable()
export class AuthService {
  constructor(
    private prisma: PrismaService,
    private config: ConfigService,
    private jwt: JwtService,
  ) {}

  async signupLocal(dto: AuthDto) {
    try {
      // TODO: generate the password hash
      const salt = await bcrypt.genSalt();
      const hash = await bcrypt.hash(dto.password, salt);

      // TODO: save user in the db
      const user = await this.prisma.user.create({
        data: { email: dto.email, hash },
      });

      // ! not recommended
      delete user.hash;

      // TODO: return jwt token
      return this.signToken(user.id, user.email);
    } catch (error) {
      if (error instanceof PrismaClientKnownRequestError) {
        if (error.code === 'P2002') {
          throw new ForbiddenException('Credentials taken');
        }
      }
      throw error;
    }
  }

  async signinLocal(dto: AuthDto) {
    // TODO: retrieve user from db
    const user = await this.prisma.user.findUnique({
      where: { email: dto.email },
    });
    // TODO: if user does not exist throw error
    if (!user) throw new ForbiddenException('Credentials incorrect');

    // TODO: compare password to hash
    const pwdMatches = await bcrypt.compare(dto.password, user.hash);
    // TODO: if password incorrect throw error
    if (!pwdMatches) throw new ForbiddenException('Credentials incorrect');

    // TODO: return jwt token
    return this.signToken(user.id, dto.email);
  }

  async signToken(
    userId: number,
    email: string,
  ): Promise<{ access_token: string }> {
    const payload = {
      sub: userId,
      email,
    };

    const secret = this.config.get<string>('JWT_SECRET');
    const token = await this.jwt.signAsync(payload, {
      secret,
      expiresIn: '15m',
    });

    return {
      access_token: token,
    };
  }
}

import { ForbiddenException, Injectable } from '@nestjs/common';
import { LocalSignupAuthDto, GoogleAuthDto } from './dto';
import * as bcrypt from 'bcrypt';
import { PrismaService } from '../prisma/prisma.service';
import { PrismaClientKnownRequestError } from '@prisma/client/runtime';
import { JwtService } from '@nestjs/jwt';
import { ConfigService } from '@nestjs/config';
import { LocalSigninAuthDto } from './dto';
import { JwtAccessAndRefreshTokenDto, JwtPayloadDto } from './dto';

@Injectable()
export class AuthService {
  constructor(
    private prisma: PrismaService,
    private config: ConfigService,
    private jwt: JwtService,
  ) {}

  async signupLocal(dto: LocalSignupAuthDto): JwtAccessAndRefreshTokenDto {
    try {
      // TODO: generate the password hash
      const salt = await bcrypt.genSalt();
      const hash = await bcrypt.hash(dto.password, salt);

      // TODO: save user in the db
      const user = await this.prisma.user.create({
        data: { email: dto.email, hash },
      });

      // TODO: generate access and refresh token
      const accessToken = await this.getAccessToken({
        sub: user.id,
        email: user.email,
      });
      const refreshToken = await this.getAccessToken({
        sub: user.id,
        email: user.email,
      });

      // ! not recommended
      this.prisma.deleteField(['hash'], user);

      // TODO: return jwt token
      return { accessToken, refreshToken };
    } catch (error) {
      if (error instanceof PrismaClientKnownRequestError) {
        if (error.code === 'P2002') {
          throw new ForbiddenException('Credentials taken');
        }
      }
      throw error;
    }
  }

  async signinLocal(dto: LocalSigninAuthDto) {
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
    return this.getNewAccessAndRefreshToken({
      sub: user.id,
      email: user.email,
    });
  }

  async signToken(
    userId: number,
    email: string,
  ): Promise<{ access_token: string }> {
    const payload = {
      sub: userId,
      email,
    };

    const secret = this.config.get<string>('JWT_ACCESS_TOKEN_SECRET');
    const token = await this.jwt.signAsync(payload, {
      secret,
      expiresIn: '15m',
    });

    return {
      access_token: token,
    };
  }

  async signinGoogle(dto: GoogleAuthDto): JwtAccessAndRefreshTokenDto {
    try {
      // TODO: get user from db
      let user = await this.prisma.user.findFirst({
        where: { email: dto.email, provider: 'google' }, // if provider not google reject
      });
      // TODO: create user in db if not exist
      if (!user) {
        user = await this.prisma.user.create({
          data: {
            email: dto.email,
            firstName: dto.firstName,
            lastName: dto.lastName,
            provider: dto.provider,
            googleAccessToken: dto.accessToken,
            googleRefreshToken: dto.refreshToken,
          },
        });
      }
      // TODO: return jwt token
      return this.getNewAccessAndRefreshToken({
        sub: user.id,
        email: user.email,
      });
    } catch (error) {
      if (error instanceof PrismaClientKnownRequestError) {
        if (error.code === 'P2002') {
          throw new ForbiddenException('Credentials taken');
        }
      }
      throw error;
    }
  }

  // TODO: create access token
  async getAccessToken(payload: JwtPayloadDto): Promise<string> {
    const accessToken = await this.jwt.signAsync(payload, {
      secret: this.config.get<string>('JWT_ACCESS_TOKEN_SECRET'),
      expiresIn: this.config.get<string>('JWT_ACCESS_TOKEN_EXPIRATION_TIME'),
    });

    return accessToken;
  }

  // TODO: create refresh token and store it (hashed)
  async getRefreshToken(payload: JwtPayloadDto): Promise<string> {
    const refreshToken = await this.jwt.signAsync(payload, {
      secret: this.config.get<string>('JWT_REFRESH_TOKEN_SECRET'),
      expiresIn: this.config.get<string>('JWT_REFRESH_TOKEN_EXPIRATION_TIME'),
    });

    return refreshToken;
  }

  // TODO: create access and refresh token
  async updateRefreshTokenInDatabase(
    refreshToken: string,
    userId: number,
  ): Promise<void> {
    // TODO: if not null hash refresh token
    const hashedRefreshToken = refreshToken
      ? await bcrypt.hash(refreshToken, await bcrypt.genSalt())
      : null;

    // TODO: update refresh token in db
    await this.prisma.user.update({
      where: { id: userId },
      data: { hashedRefreshToken },
    });
  }

  // TODO: return access and refresh token
  async getNewAccessAndRefreshToken(
    payload: JwtPayloadDto,
  ): JwtAccessAndRefreshTokenDto {
    // TODO: update old refresh token
    const refreshToken = await this.getRefreshToken(payload);
    await this.updateRefreshTokenInDatabase(refreshToken, payload.sub);

    return {
      accessToken: await this.getAccessToken(payload),
      refreshToken,
    };
  }
  // TODO:
}

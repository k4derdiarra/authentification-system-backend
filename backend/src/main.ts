import { ValidationPipe } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';

async function bootstrap() {
  const app = await NestFactory.create(AppModule);
  app.useGlobalPipes(
    new ValidationPipe({
      whitelist: true,
    }),
  );
  // const config = app.get<ConfigService>(ConfigService);
  // const port = config.get<number>('SERVER_PORT');
  console.log(
    "🚀 ~ file: main.ts ~ line 16 ~ bootstrap ~ 'hello world'",
    'hello world',
  );
  await app.listen(8080);
}
bootstrap();

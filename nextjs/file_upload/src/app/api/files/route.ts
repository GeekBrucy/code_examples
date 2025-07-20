import { NextResponse } from 'next/server';
import { readdir, stat } from 'fs/promises';
import path from 'path';
import { existsSync } from 'fs';

export async function GET() {
  try {
    const uploadsDir = path.join(process.cwd(), 'uploads');
    
    if (!existsSync(uploadsDir)) {
      return NextResponse.json({ files: [] });
    }

    const files = await readdir(uploadsDir);
    const fileList = await Promise.all(
      files.map(async (filename) => {
        const filepath = path.join(uploadsDir, filename);
        const stats = await stat(filepath);
        
        const originalName = filename.includes('-') 
          ? filename.substring(filename.indexOf('-') + 1)
          : filename;
        
        return {
          filename,
          originalName,
          size: stats.size,
          uploadedAt: stats.birthtime,
        };
      })
    );

    return NextResponse.json({ files: fileList });
  } catch (error) {
    console.error('Error listing files:', error);
    return NextResponse.json({ error: 'Failed to list files' }, { status: 500 });
  }
}
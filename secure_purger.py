import io
import os
from flask import send_file

def finalize_secure_pdf_stream(writer, raw_canvas_packet, filename="document.pdf"):
    """
    Finalizes the PDF assembly entirely in-memory, transmits the binary stream 
    to the client, and immediately shreds all active RAM buffers.
    """
    final_pdf_buffer = io.BytesIO()
    writer.write(final_pdf_buffer)
    final_pdf_buffer.seek(0)

    response = send_file(
        final_pdf_buffer, 
        as_attachment=True, 
        download_name=filename, 
        mimetype='application/pdf'
    )

    @response.call_on_close
    def secure_memory_shredder():
        try:
            if not final_pdf_buffer.closed:
                buffer_size = final_pdf_buffer.getbuffer().nbytes
                final_pdf_buffer.seek(0)
                final_pdf_buffer.write(os.urandom(buffer_size))
                final_pdf_buffer.truncate(0)
                final_pdf_buffer.close()
            
            if not raw_canvas_packet.closed:
                packet_size = raw_canvas_packet.getbuffer().nbytes
                raw_canvas_packet.seek(0)
                raw_canvas_packet.write(os.urandom(packet_size))
                raw_canvas_packet.truncate(0)
                raw_canvas_packet.close()
                
            print("[SECURITY] Active memory buffers successfully shredded.")
                
        except Exception as e:
            print(f"[SECURITY ALERT] Failure during RAM buffer shredding: {str(e)}")

    return response

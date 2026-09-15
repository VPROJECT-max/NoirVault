@preconcurrency import AVFoundation
import SwiftUI
import UIKit

struct TOTPScannerView: UIViewControllerRepresentable {
    let onResult: (Result<String, Error>) -> Void

    func makeUIViewController(context: Context) -> ScannerViewController {
        let controller = ScannerViewController()
        controller.onResult = onResult
        return controller
    }

    func updateUIViewController(_ uiViewController: ScannerViewController, context: Context) {}
}

final class ScannerViewController: UIViewController, @preconcurrency AVCaptureMetadataOutputObjectsDelegate {
    var onResult: ((Result<String, Error>) -> Void)?
    private let session = AVCaptureSession()
    private var finished = false

    override func viewDidLoad() {
        super.viewDidLoad()
        view.backgroundColor = .black
        AVCaptureDevice.requestAccess(for: .video) { [weak self] granted in
            guard let self else { return }
            if granted { self.configure() }
            else { self.finish(.failure(TOTPError.invalidSecret)) }
        }
    }

    private func configure() {
        do {
            guard let camera = AVCaptureDevice.default(for: .video) else { throw TOTPError.invalidSecret }
            let input = try AVCaptureDeviceInput(device: camera)
            guard session.canAddInput(input) else { throw TOTPError.invalidSecret }
            session.addInput(input)
            let output = AVCaptureMetadataOutput()
            guard session.canAddOutput(output) else { throw TOTPError.invalidSecret }
            session.addOutput(output)
            output.setMetadataObjectsDelegate(self, queue: .main)
            output.metadataObjectTypes = [.qr]
            let preview = AVCaptureVideoPreviewLayer(session: session)
            preview.videoGravity = .resizeAspectFill
            preview.frame = view.bounds
            view.layer.addSublayer(preview)
            DispatchQueue.global(qos: .userInitiated).async { [session] in session.startRunning() }
        } catch {
            finish(.failure(error))
        }
    }

    override func viewDidLayoutSubviews() {
        super.viewDidLayoutSubviews()
        (view.layer.sublayers?.first as? AVCaptureVideoPreviewLayer)?.frame = view.bounds
    }

    func metadataOutput(_ output: AVCaptureMetadataOutput, didOutput metadataObjects: [AVMetadataObject], from connection: AVCaptureConnection) {
        guard let value = (metadataObjects.first as? AVMetadataMachineReadableCodeObject)?.stringValue else { return }
        finish(.success(value))
    }

    private func finish(_ result: Result<String, Error>) {
        guard !finished else { return }
        finished = true
        session.stopRunning()
        DispatchQueue.main.async { self.onResult?(result) }
    }
}
